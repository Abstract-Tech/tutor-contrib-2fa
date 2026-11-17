"""Restrict partially authenticated sessions to enrollment/challenge/logout.

Studio may redeem an authorization code issued after browser MFA without
forwarding browser cookies. Other non-browser grant types remain blocked.
"""

import json
import time
from urllib.parse import urlencode

from django.conf import settings
from django.contrib.auth import logout
from django.http import HttpResponseRedirect, JsonResponse
from django.utils.deprecation import MiddlewareMixin
from django_otp import DEVICE_ID_SESSION_KEY
from django_otp.models import Device
from two_factor.utils import default_device

from .continuation import SESSION_KEY, remember_destination
from .oauth import AUTHORIZE_PATHS, remember_authorization, remember_token, verified_code_exchange
from .policy import requires_mfa

LOGIN_PATHS = {
    "/login_ajax",
    "/api/user/v1/account/login_session/",
    "/api/user/v2/account/login_session/",
    "/user_api/v1/account/login_session/",
    "/user_api/v2/account/login_session/",
}

# Public browser assets must never be redirected into the enrollment wizard:
# a background GET to setup resets its session state and invalidates the QR.
PUBLIC_ASSET_PATHS = {"/favicon.ico", "/robots.txt"}
PUBLIC_CONFIG_PATHS = {"/api/mfe_config/v1", "/api/mfe_config/v1/"}


def verified(request):
    if not request.user.is_authenticated:
        return False
    device_id = request.session.get(DEVICE_ID_SESSION_KEY)
    device = Device.from_persistent_id(device_id) if device_id else None
    return bool(device and device.confirmed and device.user_id == request.user.pk)


def gate_url():
    base = getattr(settings, "OPENEDX_2FA_LMS_URL", "").rstrip("/")
    return base + "/2fa/"


def mfa_required(status=403):
    return JsonResponse({"error": "mfa_required", "redirect_url": gate_url()}, status=status)


class RequireTwoFactorMiddleware(MiddlewareMixin):
    def process_view(self, request, view_func, view_args, view_kwargs):
        if not getattr(settings, "OPENEDX_2FA_ENABLED", False):
            return None
        path = request.path
        # Bootstrap config is public even for anonymous visitors. MFEs need it
        # before they know the login/refresh endpoints; stale JWT cookies must
        # not turn this request into an MFA-gated API request.
        if path in PUBLIC_CONFIG_PATHS and request.method in {"GET", "HEAD"}:
            return None
        if (
            path in PUBLIC_ASSET_PATHS
            or path.startswith(("/static/", "/media/"))
            or request.method == "OPTIONS"
        ):
            return None
        if path in LOGIN_PATHS and request.method == "POST":
            request.session.pop(DEVICE_ID_SESSION_KEY, None)
            request.session.pop(SESSION_KEY, None)
        # Token subjects may differ from the browser's session user. Validate
        # the grant's policy before considering browser session exemptions.
        token_request = path.startswith(("/oauth2/access_token", "/oauth2/exchange_access_token"))
        if token_request:
            return None if verified_code_exchange(request) else mfa_required()
        # A completed browser login follows Open edX's ordinary routing, JWT
        # refresh and authorization flow. Visiting another app is not a login.
        if request.user.is_authenticated and not requires_mfa(request.user):
            request.session.pop("openedx_2fa_started", None)
            request.session.pop(SESSION_KEY, None)
            if path.startswith("/2fa/") and path not in {"/2fa/", "/2fa/challenge/"}:
                return JsonResponse({"error": "mfa_enrollment_not_available"}, status=403)
            return None
        if verified(request):
            return None
        if path == "/login_refresh":
            # frontend-platform treats 401 as signed out; 403 aborts MFE startup.
            # Never issue refreshed JWTs to an unverified session.
            from openedx.core.djangoapps.user_authn.cookies import delete_logged_in_cookies

            return delete_logged_in_cookies(mfa_required(status=401))
        # DRF authenticates bearer/JWT clients after middleware. Fail closed here.
        has_credentials = bool(request.META.get("HTTP_AUTHORIZATION"))
        jwt_cookies = any(
            name.startswith("edx-jwt-cookie") and value for name, value in request.COOKIES.items()
        )
        jwt_api = jwt_cookies and path.startswith(("/api/", "/user_api/"))
        if (
            (has_credentials or jwt_api)
            and path not in LOGIN_PATHS
            and not path.startswith(("/2fa/", "/logout"))
        ):
            return mfa_required()
        if not request.user.is_authenticated:
            return None
        started = request.session.setdefault("openedx_2fa_started", time.time())
        if time.time() - started > 600:
            logout(request)
            return HttpResponseRedirect("/login?" + urlencode({"next": gate_url()}))
        if path in AUTHORIZE_PATHS and request.method == "GET":
            remember_destination(request, request.get_full_path())
            return HttpResponseRedirect(gate_url())
        if path in ("/logout", "/logout/"):
            return None
        if path.startswith("/2fa/"):
            # Never permit reenrollment or recovery-code access to bypass an existing device.
            allowed = {"/2fa/", "/2fa/challenge/"}
            if not default_device(request.user):
                allowed |= {"/2fa/account/two_factor/setup/", "/2fa/account/two_factor/qrcode/"}
            if path in allowed:
                return None
        if path in LOGIN_PATHS:
            return None
        destination = request.META.get("HTTP_SEC_FETCH_DEST")
        background_request = destination is not None and destination != "document"
        if (
            background_request
            or path.startswith(("/api/", "/user_api/", "/oauth2/"))
            or request.method != "GET"
        ):
            return mfa_required()
        remember_destination(request, request.get_full_path())
        return HttpResponseRedirect(gate_url())

    def process_response(self, request, response):
        if not getattr(settings, "OPENEDX_2FA_ENABLED", False):
            return response
        remember_token(request, response)
        if not hasattr(request, "user") or not request.user.is_authenticated:
            return response
        if verified(request) or not requires_mfa(request.user):
            remember_authorization(request, response)
            return response
        # Password login/registration may have issued Open edX JWT cookies: withhold
        # them until OTP succeeds. Keep the Django session for the MFA challenge only.
        from openedx.core.djangoapps.user_authn.cookies import delete_logged_in_cookies

        response = delete_logged_in_cookies(response)
        if request.path in LOGIN_PATHS and response.status_code == 200:
            try:
                payload = json.loads(response.content)
            except (ValueError, TypeError):
                return response
            if payload.get("success"):
                request.session["openedx_2fa_started"] = time.time()
                # Keep the platform-selected destination (including finish_auth
                # and course enrollment), rather than replacing the login flow.
                remember_destination(request, payload.get("redirect_url") or "/dashboard")
                payload["redirect_url"] = gate_url()
                response.content = json.dumps(payload)
        return response
