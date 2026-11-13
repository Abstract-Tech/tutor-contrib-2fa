"""Exercise real OAuth Toolkit validation across separate browser/server clients."""

from datetime import timedelta
from urllib.parse import parse_qs, urlsplit

import pytest
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import Client
from django.utils import timezone
from django_otp import DEVICE_ID_SESSION_KEY
from django_otp.plugins.otp_totp.models import TOTPDevice
from oauth2_provider.models import AccessToken, Application, Grant
from openedx_two_factor.oauth import proof_key

from .test_flow import cookies  # noqa: F401

pytestmark = pytest.mark.django_db
REDIRECT = "https://studio.example/complete/edx-oauth2/"


@pytest.fixture
def flow():
    cache.clear()
    user = get_user_model().objects.create_user("oauth-user", password="password")
    device = TOTPDevice.objects.create(user=user, name="default")
    application = Application.objects.create(
        name="Studio",
        client_id="studio",
        client_secret="secret",
        client_type=Application.CLIENT_CONFIDENTIAL,
        authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        redirect_uris=REDIRECT,
        skip_authorization=True,
    )
    browser = Client()
    browser.force_login(user)
    session = browser.session
    session[DEVICE_ID_SESSION_KEY] = device.persistent_id
    session.save()
    yield browser, user, device, application
    cache.clear()


def authorize(browser, **overrides):
    params = dict(
        client_id="studio", response_type="code", redirect_uri=REDIRECT, scope="read", state="state"
    )
    params.update(overrides)
    return browser.get("/oauth2/authorize", params)


def code_for(browser, **overrides):
    response = authorize(browser, **overrides)
    assert response.status_code == 302
    return parse_qs(urlsplit(response.url).query)["code"][0]


def exchange(code, **overrides):
    params = dict(
        grant_type="authorization_code",
        code=code,
        client_id="studio",
        client_secret="secret",
        redirect_uri=REDIRECT,
    )
    params.update(overrides)
    return Client().post("/oauth2/access_token", params)


def test_studio_exchanges_mfa_code_without_browser_cookies(flow):
    browser, user, _, application = flow
    code = code_for(browser)
    response = exchange(code)
    assert response.status_code == 200, response.content
    token = AccessToken.objects.get(token=response.json()["access_token"])
    assert token.user_id == user.pk
    assert token.application_id == application.pk
    assert exchange(code).status_code == 403


@pytest.mark.parametrize(
    "overrides",
    [
        {"client_secret": "wrong"},
        {"client_id": "other"},
        {"redirect_uri": "https://attacker.example/"},
    ],
)
def test_oauth_still_checks_client_and_redirect(flow, overrides):
    code = code_for(flow[0])
    assert exchange(code, **overrides).status_code in (400, 401)
    assert not AccessToken.objects.exists()


def test_pkce_is_still_required(flow):
    code = code_for(flow[0], code_challenge="challenge", code_challenge_method="plain")
    assert exchange(code, code_verifier="wrong").status_code == 400
    assert not AccessToken.objects.exists()
    assert exchange(code, code_verifier="challenge").status_code == 200


@pytest.mark.parametrize("invalidate", ["cache", "expiry", "device", "unconfirmed", "owner"])
def test_missing_or_invalid_mfa_proof_is_denied(flow, invalidate):
    browser, _, device, _ = flow
    code = code_for(browser)
    if invalidate == "cache":
        cache.delete(proof_key(code))
    elif invalidate == "expiry":
        Grant.objects.filter(code=code).update(expires=timezone.now() - timedelta(seconds=1))
    elif invalidate == "device":
        device.delete()
    elif invalidate == "unconfirmed":
        device.confirmed = False
        device.save()
    else:
        device.user = get_user_model().objects.create_user("other")
        device.save()
    assert exchange(code).status_code == 403
    assert not AccessToken.objects.exists()


def test_legacy_unverified_grant_cannot_be_redeemed(flow):
    _, user, _, application = flow
    Grant.objects.create(
        user=user,
        application=application,
        code="old-code",
        redirect_uri=REDIRECT,
        scope="read",
        expires=timezone.now() + timedelta(minutes=1),
    )
    assert exchange("old-code").status_code == 403


@pytest.mark.parametrize("grant_type", ["password", "client_credentials", "refresh_token"])
def test_other_grant_types_are_not_exempted(flow, grant_type):
    code = code_for(flow[0])
    assert exchange(code, grant_type=grant_type).status_code == 403


def test_partial_session_resumes_authorization_after_mfa(flow):
    browser, _, device, _ = flow
    session = browser.session
    del session[DEVICE_ID_SESSION_KEY]
    session.save()
    response = authorize(browser)
    assert response.url == "/2fa/"
    assert not Grant.objects.exists()
    next_url = browser.session["openedx_2fa_login_destination"]["url"]
    assert next_url.startswith("/oauth2/authorize?")
    session = browser.session
    session[DEVICE_ID_SESSION_KEY] = device.persistent_id
    session.save()
    assert browser.get("/2fa/").url == next_url
    response = browser.get(next_url)
    code = parse_qs(urlsplit(response.url).query)["code"][0]
    assert exchange(code).status_code == 200


def test_resume_cannot_redirect_to_external_site(flow):
    browser = flow[0]
    session = browser.session
    session["openedx_2fa_login_destination"] = {
        "user_id": flow[1].pk,
        "url": "https://attacker.example/oauth2/authorize",
    }
    session.save()
    assert browser.get("/2fa/").status_code == 200


def test_disabled_integration_uses_normal_oauth(flow, settings):
    settings.OPENEDX_2FA_ENABLED = False
    code = code_for(flow[0])
    assert cache.get(proof_key(code)) is None
    assert exchange(code).status_code == 200


def test_studio_login_persists_mfa_in_new_session(flow):
    from types import SimpleNamespace

    from django.contrib.auth import login
    from django.contrib.auth.models import AnonymousUser
    from django.test import RequestFactory
    from openedx_two_factor.middleware import verified
    from openedx_two_factor.oauth import restore_studio_mfa, token_proof_key

    browser, user, device, _ = flow
    payload = exchange(code_for(browser)).json()
    backend = SimpleNamespace(name="edx-oauth2", setting=lambda name: "studio")
    restore_studio_mfa(backend, user=user, response=payload)
    request = RequestFactory().get("/complete/edx-oauth2/")
    request.user = AnonymousUser()
    request.session = Client().session
    login(request, user, backend="django.contrib.auth.backends.ModelBackend")
    assert request.session[DEVICE_ID_SESSION_KEY] == device.persistent_id
    assert verified(request)
    assert cache.get(token_proof_key(payload["access_token"])) is None


@pytest.mark.parametrize("invalid", ["token", "user", "client", "device", "expired"])
def test_studio_rejects_unbound_mfa_proof(flow, invalid):
    from types import SimpleNamespace

    from django.core.exceptions import PermissionDenied
    from openedx_two_factor.oauth import restore_studio_mfa, token_proof_key

    browser, user, device, _ = flow
    payload = exchange(code_for(browser)).json()
    client_id = "studio"
    if invalid == "token":
        payload["access_token"] = "forged"
    elif invalid == "user":
        user = get_user_model().objects.create_user("different-user")
    elif invalid == "client":
        client_id = "other-client"
    elif invalid == "device":
        device.delete()
    else:
        cache.delete(token_proof_key(payload["access_token"]))
    backend = SimpleNamespace(name="edx-oauth2", setting=lambda name: client_id)
    with pytest.raises(PermissionDenied):
        restore_studio_mfa(backend, user=user, response=payload)


def test_studio_pipeline_keeps_existing_steps(settings):
    # Runtime dependency is provided by Open edX; use a minimal strategy in unit tests.
    import sys
    import types
    from unittest.mock import patch

    from openedx_two_factor.oauth import configure_studio_pipeline

    strategy = types.ModuleType("auth_backends.strategies")
    strategy.EdxDjangoStrategy = types.SimpleNamespace(
        DEFAULT_SETTINGS={"SOCIAL_AUTH_PIPELINE": ["default"]}
    )
    settings.SOCIAL_AUTH_EDX_OAUTH2_KEY = "studio"
    settings.SOCIAL_AUTH_EDX_OAUTH2_PIPELINE = ["custom"]
    with patch.dict(sys.modules, {"auth_backends.strategies": strategy}):
        configure_studio_pipeline()
        configure_studio_pipeline()
    assert settings.SOCIAL_AUTH_EDX_OAUTH2_PIPELINE == [
        "custom",
        "openedx_two_factor.oauth.restore_studio_mfa",
    ]
