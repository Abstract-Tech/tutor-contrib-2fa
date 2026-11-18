import sys
import time
import types

import pytest
from django.contrib.auth import get_user_model
from django.test import Client
from django_otp import DEVICE_ID_SESSION_KEY
from django_otp.oath import totp
from django_otp.plugins.otp_static.models import StaticDevice, StaticToken
from django_otp.plugins.otp_totp.models import TOTPDevice
from openedx_two_factor.continuation import SESSION_KEY

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def cookies(monkeypatch):
    module = types.ModuleType("openedx.core.djangoapps.user_authn.cookies")

    def delete(response):
        response.delete_cookie("edx-jwt-cookie-header-payload")
        return response

    def set_cookies(request, response, user):
        response.set_cookie("edx-jwt-cookie-header-payload", "verified-token")
        return response

    module.delete_logged_in_cookies = delete
    module.set_logged_in_cookies = set_cookies
    monkeypatch.setitem(sys.modules, module.__name__, module)


@pytest.fixture
def user():
    return get_user_model().objects.create_user("learner", password="test-password", is_staff=True)


@pytest.fixture
def device(user):
    return TOTPDevice.objects.create(user=user, name="default")


def sign_in(client):
    return client.post("/login_ajax", {"username": "learner", "password": "test-password"})


def token(device):
    return f"{totp(device.bin_key, step=device.step, t0=device.t0, digits=device.digits):06d}"


def test_password_login_withholds_jwt_and_redirects(client, user):
    response = sign_in(client)
    assert response.json()["redirect_url"] == "/2fa/"
    assert response.cookies["edx-jwt-cookie-header-payload"]["max-age"] == 0
    assert client.get("/dashboard").url == "/2fa/"
    assert client.get("/api/protected/").status_code == 403
    assert client.get("/admin/").url == "/2fa/"


def test_enrollment_page_and_qr_flow(client, user):
    sign_in(client)
    assert client.get("/2fa/").url.endswith("/setup/")
    url = "/2fa/account/two_factor/setup/"
    response = client.get(url)
    assert response.status_code == 200
    response = client.post(url, {"two_factor_setup_view-current_step": "welcome"})
    assert response.status_code == 200
    assert b"TOTP Secret" in response.content
    assert client.get("/2fa/account/two_factor/qrcode/").status_code == 200


def test_valid_otp_opens_session_and_rejects_replay(client, user, device):
    sign_in(client)
    value = token(device)
    response = client.post("/2fa/challenge/", {"otp_token": value})
    assert response.status_code == 302
    assert client.get("/dashboard").status_code == 200
    assert client.get("/2fa/").cookies["edx-jwt-cookie-header-payload"].value == "verified-token"
    client.get("/logout")
    sign_in(client)
    assert client.post("/2fa/challenge/", {"otp_token": value}).status_code == 200
    assert DEVICE_ID_SESSION_KEY not in client.session


def test_wrong_code_and_reenrollment_blocked(client, user, device):
    sign_in(client)
    assert client.post("/2fa/challenge/", {"otp_token": "invalid"}).status_code == 200
    assert client.get("/2fa/account/two_factor/setup/").url == "/2fa/"
    assert client.get("/2fa/account/two_factor/backup/tokens/").url == "/2fa/"
    assert DEVICE_ID_SESSION_KEY not in client.session


def test_recovery_code_is_single_use(client, user, device):
    backup = StaticDevice.objects.create(user=user, name="backup")
    StaticToken.objects.create(device=backup, token="one-use-code")
    sign_in(client)
    assert (
        client.post("/2fa/challenge/?recovery=1", {"otp_token": "one-use-code"}).status_code == 302
    )
    assert client.get("/dashboard").status_code == 200
    assert not backup.token_set.exists()
    client.get("/logout")
    sign_in(client)
    assert (
        client.post("/2fa/challenge/?recovery=1", {"otp_token": "one-use-code"}).status_code == 200
    )
    assert DEVICE_ID_SESSION_KEY not in client.session


def test_expired_partial_session_logs_out(client, user):
    sign_in(client)
    session = client.session
    session["openedx_2fa_started"] = time.time() - 601
    session.save()
    assert client.get("/2fa/").url.startswith("/login?")
    assert "_auth_user_id" not in client.session


def test_token_endpoints_and_bearer_without_verified_session_denied(client):
    assert client.post("/oauth2/access_token").status_code == 403
    assert client.get("/api/protected/", HTTP_AUTHORIZATION="Bearer test").status_code == 403
    client.cookies["edx-jwt-cookie-header-payload"] = "old-token"
    assert client.get("/api/protected/").status_code == 403


@pytest.mark.parametrize("path", ["/api/mfe_config/v1", "/api/mfe_config/v1/"])
@pytest.mark.parametrize("partial_login", [False, True])
def test_public_mfe_config_loads_before_mfa_with_stale_jwt(client, user, path, partial_login):
    if partial_login:
        sign_in(client)
    client.cookies["edx-jwt-cookie-header-payload"] = "old-token"
    assert client.get(path).json()["LMS_BASE_URL"] == "http://lms"
    assert client.head(path).status_code == 200
    assert client.post(path).status_code == 403
    assert client.get("/api/protected/").status_code == 403
    assert client.post("/oauth2/access_token").status_code == 403


def test_csrf_required(user, device):
    client = Client(enforce_csrf_checks=True)
    client.force_login(user)
    assert client.post("/2fa/challenge/", {"otp_token": token(device)}).status_code == 403


@pytest.mark.parametrize("partial_login", [False, True])
def test_refresh_reports_signed_out_until_mfa(client, user, partial_login):
    if partial_login:
        sign_in(client)
    client.cookies["edx-jwt-cookie-header-payload"] = "old-token"
    response = client.post("/login_refresh")
    assert response.status_code == 401
    assert response.cookies["edx-jwt-cookie-header-payload"]["max-age"] == 0


def test_verified_session_can_refresh(client, user, device):
    sign_in(client)
    client.post("/2fa/challenge/", {"otp_token": token(device)})
    assert client.post("/login_refresh").json()["refreshed"] is True


def test_deleted_device_invalidates_session(client, user, device):
    sign_in(client)
    client.post("/2fa/challenge/", {"otp_token": token(device)})
    device.delete()
    assert client.get("/dashboard").url == "/2fa/"


def test_complete_enrollment_and_generate_recovery_codes(client, user, monkeypatch):
    import base64

    sign_in(client)
    url = "/2fa/account/two_factor/setup/"
    client.get(url)
    response = client.post(url, {"two_factor_setup_view-current_step": "welcome"})
    secret = response.context["secret_key"]
    value = f"{totp(base64.b32decode(secret)):06d}"
    response = client.post(
        url, {"two_factor_setup_view-current_step": "generator", "generator-token": value}
    )
    assert response.status_code == 302
    assert response.url == "/2fa/account/two_factor/backup/tokens/"
    assert client.get(response.url).status_code == 200
    assert not StaticToken.objects.filter(device__user=user).exists()
    assert client.session[SESSION_KEY]["url"] == "/dashboard"
    assert TOTPDevice.objects.filter(user=user, confirmed=True).count() == 1
    assert client.get("/dashboard").status_code == 302
    response = manage_recovery(client, TOTPDevice.objects.get(user=user), monkeypatch)
    assert response.status_code == 200
    assert len(response.context["codes"]) == 10
    assert StaticToken.objects.filter(device__user=user).count() == 10
    assert client.get("/2fa/account/two_factor/backup/tokens/").status_code == 200

    assert client.get("/2fa/account/two_factor/").url == RECOVERY_URL
    assert client.post(
        RECOVERY_URL, {"action": "acknowledge", "receipt": response.context["receipt"]}
    ).json()["saved"]
    # The page's Continue link resumes the original login flow.
    response = client.get("/2fa/account/two_factor/")
    assert response.status_code == 302
    assert response.url == "/dashboard"
    assert SESSION_KEY not in client.session


def test_bad_token_throttles(client, user, device):
    sign_in(client)
    wrong = "111111" if token(device) != "111111" else "222222"
    client.post("/2fa/challenge/", {"otp_token": wrong})
    device.refresh_from_db()
    assert device.throttling_failure_count == 1
    assert not device.verify_is_allowed()[0]


def test_new_password_login_clears_verification(client, user, device):
    sign_in(client)
    client.post("/2fa/challenge/", {"otp_token": token(device)})
    assert DEVICE_ID_SESSION_KEY in client.session
    sign_in(client)
    assert DEVICE_ID_SESSION_KEY not in client.session


def test_otp_pages_excluded_from_openedx_request_tracking(settings):
    import re

    assert any(
        re.match(pattern, "/2fa/challenge/") for pattern in settings.TRACKING_IGNORE_URL_PATTERNS
    )


def test_browser_favicon_request_does_not_reset_enrollment(client, user):
    import base64

    sign_in(client)
    url = "/2fa/account/two_factor/setup/"
    client.get(url)
    page = client.post(url, {"two_factor_setup_view-current_step": "welcome"})
    secret = page.context["secret_key"]
    # Browsers automatically fetch the favicon and follow HTTP redirects.
    client.get("/favicon.ico", follow=True, HTTP_SEC_FETCH_DEST="image")
    value = f"{totp(base64.b32decode(secret)):06d}"
    response = client.post(
        url,
        {
            "two_factor_setup_view-current_step": "generator",
            "generator-token": value,
        },
    )
    assert response.status_code == 302
    assert TOTPDevice.objects.filter(user=user, confirmed=True).exists()


@pytest.mark.parametrize("destination", ["image", "script", "style", "empty", "iframe"])
def test_background_requests_do_not_redirect_or_reset_setup(client, user, destination):
    import base64

    sign_in(client)
    url = "/2fa/account/two_factor/setup/"
    client.get(url)
    page = client.post(url, {"two_factor_setup_view-current_step": "welcome"})
    secret = page.context["secret_key"]
    denied = client.get("/dashboard", follow=True, HTTP_SEC_FETCH_DEST=destination)
    assert denied.status_code == 403
    assert not denied.redirect_chain
    value = f"{totp(base64.b32decode(secret)):06d}"
    response = client.post(
        url,
        {
            "two_factor_setup_view-current_step": "generator",
            "generator-token": value,
        },
    )
    assert response.status_code == 302
    assert TOTPDevice.objects.filter(user=user, confirmed=True).exists()


def test_disabled_integration_leaves_login_and_api_access_unchanged(user, settings):
    settings.OPENEDX_2FA_ENABLED = False
    client = Client()
    response = sign_in(client)
    assert response.status_code == 200
    assert response.json()["redirect_url"] == "/dashboard"
    assert response.cookies["edx-jwt-cookie-header-payload"].value == "first-factor-token"
    assert client.get("/dashboard").status_code == 200
    response = client.get("/api/protected/", HTTP_AUTHORIZATION="Bearer test")
    assert response.status_code == 200


def password_login(client, destination):
    return client.post(
        "/login_ajax",
        {
            "username": "learner",
            "password": "test-password",
            "next": destination,
        },
    )


@pytest.mark.parametrize(
    "destination",
    [
        "/dashboard",
        "/courses/course-v1:Org+Course+Run/course/",
        "/account/finish_auth/?course_id=course-v1%3AOrg%2BCourse%2BRun&enrollment_action=enroll",
        "https://apps.example/learning/course/course-v1:Org+Course+Run/home",
    ],
)
def test_login_resumes_original_destination_after_mfa(client, user, device, settings, destination):
    settings.LOGIN_REDIRECT_WHITELIST = ["apps.example"]
    assert password_login(client, destination).json()["redirect_url"] == "/2fa/"
    assert DEVICE_ID_SESSION_KEY not in client.session
    response = client.post("/2fa/challenge/", {"otp_token": token(device)})
    assert response.url == "/2fa/"
    assert client.get("/2fa/").url == destination
    assert SESSION_KEY not in client.session
    assert client.get("/api/protected/").status_code == 200
    assert client.post("/login_refresh").status_code == 200


@pytest.mark.parametrize(
    "destination",
    [
        "https://attacker.example/",
        "//attacker.example/",
        "javascript:alert(1)",
        "/\\attacker.example/",
        "/2fa/challenge/",
        "/logout",
    ],
)
def test_untrusted_or_looping_destinations_are_not_saved(client, user, destination):
    password_login(client, destination)
    assert SESSION_KEY not in client.session


def test_pending_destination_cannot_transfer_to_another_user(client, user, device):
    sign_in(client)
    client.post("/2fa/challenge/", {"otp_token": token(device)})
    session = client.session
    session[SESSION_KEY] = {"user_id": user.pk + 1, "url": "/dashboard"}
    session.save()
    assert client.get("/2fa/").status_code == 200


def test_repeated_verified_visits_do_not_rotate_session_or_challenge(client, user, device):
    sign_in(client)
    client.post("/2fa/challenge/", {"otp_token": token(device)})
    client.get("/2fa/")
    session_key = client.session.session_key
    for _ in range(2):
        assert client.get("/dashboard").status_code == 200
        assert client.get("/api/protected/", HTTP_AUTHORIZATION="JWT token").status_code == 200
        assert client.post("/login_refresh").status_code == 200
        assert client.get("/2fa/").status_code == 200
        assert client.session.session_key == session_key


def test_logout_requires_mfa_on_next_login(client, user, device):
    sign_in(client)
    client.post("/2fa/challenge/", {"otp_token": token(device)})
    client.get("/logout")
    password_login(client, "/dashboard")
    assert DEVICE_ID_SESSION_KEY not in client.session
    assert client.get("/dashboard").url == "/2fa/"


def test_protected_browser_page_resumes_after_mfa(client, user, device):
    sign_in(client)
    assert client.get("/dashboard?tab=courses").url == "/2fa/"
    client.post("/2fa/challenge/", {"otp_token": token(device)})
    assert client.get("/2fa/").url == "/dashboard?tab=courses"


RECOVERY_URL = "/2fa/account/two_factor/backup/tokens/"


def manage_recovery(client, device, monkeypatch, action="generate", confirm=True):
    return client.post(RECOVERY_URL, {"action": action, "confirm": confirm})


def test_recovery_view_and_replace(client, user, device, monkeypatch):
    sign_in(client)
    client.post("/2fa/challenge/", {"otp_token": token(device)})
    assert client.get(RECOVERY_URL).context["issued"] is False
    generated = manage_recovery(client, device, monkeypatch)
    codes = generated.context["codes"]
    assert len(codes) == 10
    assert "no-store" in generated["Cache-Control"]
    assert client.get(RECOVERY_URL).context["codes"] == codes
    viewed = client.get(RECOVERY_URL)
    assert viewed.context["codes"] == codes
    assert b"copy-recovery-codes" in viewed.content
    replaced = manage_recovery(client, device, monkeypatch)
    assert replaced.status_code == 200
    new_codes = replaced.context["codes"]
    assert len(new_codes) == 10 and not set(new_codes) & set(codes)
    assert not StaticToken.objects.filter(device__user=user, token__in=codes).exists()
    backup = StaticDevice.objects.get(user=user, name="backup")
    assert backup.verify_token(new_codes[0])
    assert not backup.token_set.filter(token=new_codes[0]).exists()
    assert new_codes[0] not in client.get(RECOVERY_URL).context["codes"]


def test_recovery_requires_verified_session_and_replacement_confirmation(
    client, user, device, monkeypatch
):
    sign_in(client)
    assert client.post(RECOVERY_URL, {"action": "generate"}).status_code == 403
    assert not StaticToken.objects.filter(device__user=user).exists()
    client.post("/2fa/challenge/", {"otp_token": token(device)})
    assert b'name="otp_token"' not in client.get(RECOVERY_URL).content
    codes = manage_recovery(client, device, monkeypatch).context["codes"]
    assert manage_recovery(client, device, monkeypatch, confirm=False).status_code == 400
    assert client.post(RECOVERY_URL, {"action": "invalid"}).status_code == 400
    assert set(
        StaticToken.objects.filter(device__user=user).values_list("token", flat=True)
    ) == set(codes)
    assert client.get(RECOVERY_URL).context["codes"] == codes


@pytest.mark.parametrize("with_codes", [False, True])
def test_legacy_and_exhausted_recovery_codes_can_be_replaced(
    client, user, device, monkeypatch, with_codes
):
    backup = StaticDevice.objects.create(user=user, name="backup")
    duplicate = StaticDevice.objects.create(user=user, name="backup")
    if with_codes:
        StaticToken.objects.create(device=backup, token="legacy-code")
        StaticToken.objects.create(device=duplicate, token="duplicate-code")
    sign_in(client)
    client.post("/2fa/challenge/", {"otp_token": token(device)})
    assert client.get(RECOVERY_URL).status_code == 200
    assert manage_recovery(client, device, monkeypatch).status_code == 200
    assert StaticToken.objects.filter(device__user=user).count() == 10
    assert not StaticToken.objects.filter(token__in=["legacy-code", "duplicate-code"]).exists()


def test_recovery_generation_requires_csrf(user, device):
    client = Client(enforce_csrf_checks=True)
    client.force_login(user)
    session = client.session
    session[DEVICE_ID_SESSION_KEY] = device.persistent_id
    session.save()
    assert client.post(RECOVERY_URL).status_code == 403
    assert not StaticDevice.objects.filter(user=user).exists()


def test_recovery_render_failure_preserves_old_codes(client, user, device, monkeypatch):
    sign_in(client)
    client.post("/2fa/challenge/", {"otp_token": token(device)})
    codes = manage_recovery(client, device, monkeypatch).context["codes"]

    def fail(*args, **kwargs):
        raise RuntimeError("render failed")

    monkeypatch.setattr("openedx_two_factor.recovery.render", fail)
    with pytest.raises(RuntimeError, match="render failed"):
        manage_recovery(client, device, monkeypatch)
    assert set(
        StaticToken.objects.filter(device__user=user).values_list("token", flat=True)
    ) == set(codes)


def test_incomplete_recovery_resumes_after_new_login(client, user, device, monkeypatch):
    sign_in(client)
    client.post("/2fa/challenge/", {"otp_token": token(device)})
    assert b"Skip for now" not in client.get(RECOVERY_URL).content
    assert client.get("/2fa/account/two_factor/").status_code == 302
    client.logout()
    sign_in(client)
    now = time.time() + 31
    monkeypatch.setattr("time.time", lambda: now)
    monkeypatch.setattr("django_otp.oath.time", lambda: now)
    client.post("/2fa/challenge/", {"otp_token": token(device)})
    assert manage_recovery(client, device, monkeypatch).status_code == 200


@pytest.mark.parametrize(
    "origin, expected",
    [("http://testserver", 200), ("null", 403), ("https://untrusted.example", 403)],
)
def test_recovery_form_origin_protection(user, device, origin, expected):
    client = Client(enforce_csrf_checks=True)
    client.force_login(user)
    session = client.session
    session[DEVICE_ID_SESSION_KEY] = device.persistent_id
    session.save()
    page = client.get(RECOVERY_URL)
    assert page["Referrer-Policy"] == "same-origin"
    response = client.post(
        RECOVERY_URL,
        {
            "action": "generate",
            "csrfmiddlewaretoken": client.cookies["csrftoken"].value,
        },
        HTTP_ORIGIN=origin,
    )
    assert response.status_code == expected
    assert StaticToken.objects.filter(device__user=user).count() == (10 if expected == 200 else 0)


def test_copy_acknowledgement_gates_access_and_survives_sessions(client, user, device):
    from openedx_two_factor.models import RecoverySetup

    sign_in(client)
    client.post("/2fa/challenge/", {"otp_token": token(device)})
    generated = client.post(RECOVERY_URL, {"action": "generate"})
    receipt = generated.context["receipt"]
    codes = generated.context["codes"]
    assert b'id="recovery-continue" type="submit" disabled' in generated.content
    assert b"print-recovery-codes" not in generated.content
    assert client.get("/2fa/").url == RECOVERY_URL
    assert client.get("/dashboard").status_code == 302
    assert client.get("/api/protected/").status_code == 403
    assert client.post("/login_refresh").status_code == 401
    assert (
        "edx-jwt-cookie-header-payload" not in client.cookies
        or not client.cookies["edx-jwt-cookie-header-payload"].value
    )
    client.logout()
    client.force_login(user)
    session = client.session
    session[DEVICE_ID_SESSION_KEY] = device.persistent_id
    session.save()
    assert client.get("/2fa/").url == RECOVERY_URL
    assert client.get(RECOVERY_URL).context["codes"] == codes
    assert client.post(RECOVERY_URL, {"action": "acknowledge", "receipt": receipt}).json() == {
        "saved": True
    }
    assert RecoverySetup.objects.get(user=user).saved_at is not None
    assert client.get("/dashboard").status_code == 200
    assert client.get("/api/protected/").status_code == 200
    assert client.get(RECOVERY_URL).context["saved"]


def test_recovery_acknowledgement_rejects_missing_foreign_stale_receipts(client, user, device):
    from django.core import signing
    from openedx_two_factor.models import RecoverySetup

    sign_in(client)
    client.post("/2fa/challenge/", {"otp_token": token(device)})
    assert (
        client.post(RECOVERY_URL, {"action": "acknowledge", "receipt": "forged"}).status_code == 400
    )
    generated = client.post(RECOVERY_URL, {"action": "generate"})
    receipt = generated.context["receipt"]
    payload = signing.loads(receipt, salt="2fa-recovery-save")
    payload["user"] += 1
    foreign = signing.dumps(payload, salt="2fa-recovery-save")
    assert (
        client.post(RECOVERY_URL, {"action": "acknowledge", "receipt": foreign}).status_code == 409
    )
    replaced = client.post(RECOVERY_URL, {"action": "generate", "confirm": True})
    assert (
        client.post(RECOVERY_URL, {"action": "acknowledge", "receipt": receipt}).status_code == 409
    )
    assert RecoverySetup.objects.get(user=user).saved_at is None
    assert (
        client.post(
            RECOVERY_URL, {"action": "acknowledge", "receipt": replaced.context["receipt"]}
        ).status_code
        == 200
    )
    client.post(RECOVERY_URL, {"action": "generate", "confirm": True})
    assert RecoverySetup.objects.get(user=user).saved_at is None
    assert client.get("/2fa/").url == RECOVERY_URL
