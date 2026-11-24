"""A listed path may be read with a Bearer header; the view then checks its own token.

Example: the platform health API, which the Heartbeat hub calls with a shared token and no browser session.
"""

import pytest
from django.test import Client

pytestmark = pytest.mark.django_db
SUMMARY = "/api/platform_health/v1/summary"


@pytest.fixture
def listed(settings):
    settings.OPENEDX_2FA_TOKEN_PATHS = [SUMMARY]


def get(path=SUMMARY, **headers):
    return Client().get(path, **headers)


def test_blocked_by_default(settings):
    settings.OPENEDX_2FA_TOKEN_PATHS = []
    response = get(HTTP_AUTHORIZATION="Bearer token")
    assert response.status_code == 403
    assert response.json()["error"] == "mfa_required"


def test_listed_path_with_a_bearer_header_reaches_the_view(listed):
    assert get(HTTP_AUTHORIZATION="Bearer token").status_code == 200
    assert get(HTTP_AUTHORIZATION="bearer token").status_code == 200


def test_listing_changes_nothing_without_a_real_bearer_token(settings):
    # no header, an empty bearer or another scheme: the answer must be the same with and without the setting
    for headers in (
        {},
        {"HTTP_AUTHORIZATION": "Bearer"},
        {"HTTP_AUTHORIZATION": "Basic dXNlcjpwYXNz"},
    ):
        settings.OPENEDX_2FA_TOKEN_PATHS = []
        before = get(**headers).status_code
        settings.OPENEDX_2FA_TOKEN_PATHS = [SUMMARY]
        assert get(**headers).status_code == before, headers
    assert get(HTTP_AUTHORIZATION="Basic dXNlcjpwYXNz").status_code == 403


def test_only_get_is_let_through(listed):
    for method in ("post", "put", "delete", "patch"):
        response = getattr(Client(), method)(SUMMARY, HTTP_AUTHORIZATION="Bearer token")
        assert response.status_code == 403, method


def test_only_the_exact_path_is_let_through(listed):
    for path in (
        SUMMARY + "/",
        SUMMARY + "/extra",
        "/api/platform_health/v1/other",
        "/api/protected/",
    ):
        assert get(path, HTTP_AUTHORIZATION="Bearer token").status_code in (403, 404), path
    assert get("/api/protected/", HTTP_AUTHORIZATION="Bearer token").status_code == 403
