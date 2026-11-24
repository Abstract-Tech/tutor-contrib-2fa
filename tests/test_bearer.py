"""Bearer API calls are blocked, except from allow-listed OAuth apps after a verified browser login.

Open edX clients such as a storefront receive a token through the authorization-code flow, which already
required browser MFA (see test_oauth). They then read the user's account with that token and no cookies.
"""

from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import Client
from django.utils import timezone
from django_otp import DEVICE_ID_SESSION_KEY
from django_otp.plugins.otp_totp.models import TOTPDevice
from oauth2_provider.models import AccessToken, Application

from .test_oauth import REDIRECT, code_for, exchange

pytestmark = pytest.mark.django_db
ACCOUNT = "/api/user/v1/accounts/oauth-user"


def bearer(token, path=ACCOUNT, method="get"):
    return getattr(Client(), method)(path, HTTP_AUTHORIZATION=f"Bearer {token}")


@pytest.fixture
def storefront(settings):
    cache.clear()
    settings.OPENEDX_2FA_BEARER_APPLICATIONS = ["storefront"]
    user = get_user_model().objects.create_user("oauth-user", password="password", is_staff=True)
    device = TOTPDevice.objects.create(user=user, name="default")
    for name in ("storefront", "other"):
        Application.objects.create(
            name=name,
            client_id=name,
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
    yield browser, user, device
    cache.clear()


def token_for(browser, client_id="storefront"):
    response = exchange(code_for(browser, client_id=client_id), client_id=client_id)
    assert response.status_code == 200, response.content
    return response.json()["access_token"]


def test_verified_token_can_read_the_account(storefront):
    token = token_for(storefront[0])
    assert bearer(token).status_code == 200


def test_not_allowed_by_default(storefront, settings):
    settings.OPENEDX_2FA_BEARER_APPLICATIONS = []
    token = token_for(storefront[0])
    assert bearer(token).status_code == 403


def test_other_applications_stay_blocked(storefront):
    token = token_for(storefront[0], client_id="other")
    assert bearer(token).status_code == 403


@pytest.mark.parametrize(
    "path,method",
    [
        ("/api/protected/", "get"),
        ("/api/user/v1/accounts/", "get"),
        (ACCOUNT + "/extra", "get"),
        (ACCOUNT, "post"),
        (ACCOUNT, "delete"),
    ],
)
def test_only_the_account_read_is_allowed(storefront, path, method):
    token = token_for(storefront[0])
    assert bearer(token, path, method).status_code == 403


@pytest.mark.parametrize("header", ["Bearer unknown", "Bearer", "Basic abc", "JWT token"])
def test_unknown_or_malformed_credentials_are_blocked(storefront, header):
    token_for(storefront[0])
    assert Client().get(ACCOUNT, HTTP_AUTHORIZATION=header).status_code == 403


@pytest.mark.parametrize("invalidate", ["cache", "expiry", "device", "unconfirmed", "owner"])
def test_missing_or_invalid_proof_fails_closed(storefront, invalidate):
    browser, _, device = storefront
    token = token_for(browser)
    if invalidate == "cache":
        cache.clear()
    elif invalidate == "expiry":
        AccessToken.objects.filter(token=token).update(
            expires=timezone.now() - timedelta(seconds=1)
        )
    elif invalidate == "device":
        device.delete()
    elif invalidate == "unconfirmed":
        device.confirmed = False
        device.save()
    else:
        device.user = get_user_model().objects.create_user("someone-else")
        device.save()
    assert bearer(token).status_code == 403


def test_token_of_another_user_is_not_accepted(storefront):
    browser, _, _ = storefront
    token = token_for(browser)
    AccessToken.objects.filter(token=token).update(
        user=get_user_model().objects.create_user("intruder")
    )
    assert bearer(token).status_code == 403


def test_user_without_mfa_policy_needs_no_device(storefront):
    browser, user, device = storefront
    user.is_staff = False
    user.save()
    device.delete()
    token = token_for(browser)
    assert bearer(token).status_code == 200
