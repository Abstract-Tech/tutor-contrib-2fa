"""Restrict partially authenticated sessions to enrollment/challenge/logout.

This integration requires a verified browser session for token APIs.
It is not a mobile/service-client MFA implementation.
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


def verified(request):
    if not request.user.is_authenticated:
        return False
    device_id = request.session.get(DEVICE_ID_SESSION_KEY)
    device = Device.from_persistent_id(device_id) if device_id else None
    return bool(device and device.confirmed and device.user_id == request.user.pk)


def gate_url(request):
    base = getattr(settings, "OPENEDX_2FA_LMS_URL", "").rstrip("/")
    return base + "/2fa/"


class RequireTwoFactorMiddleware(MiddlewareMixin):
    def process_view(self, request, view_func, view_args, view_kwargs):
        path = request.path
        if (
            path in PUBLIC_ASSET_PATHS
            or path.startswith(("/static/", "/media/"))
            or request.method == "OPTIONS"
        ):
            return None
        if path in LOGIN_PATHS and request.method == "POST":
            request.session.pop(DEVICE_ID_SESSION_KEY, None)
        is_verified = verified(request)
        # DRF authenticates bearer/JWT clients after middleware. Fail closed here.
        token_request = path.startswith(("/oauth2/access_token", "/oauth2/exchange_access_token"))
        has_credentials = bool(request.META.get("HTTP_AUTHORIZATION"))
        jwt_cookies = any(
            name.startswith("edx-jwt-cookie") and value for name, value in request.COOKIES.items()
        )
        jwt_api = jwt_cookies and (
            path.startswith(("/api/", "/user_api/")) or path == "/login_refresh"
        )
        if (token_request or has_credentials or jwt_api) and not is_verified:
            if path not in LOGIN_PATHS and not path.startswith(("/2fa/", "/logout")):
                return JsonResponse(
                    {"error": "mfa_required", "redirect_url": gate_url(request)}, status=403
                )
        if not request.user.is_authenticated or is_verified:
            return None
        started = request.session.setdefault("openedx_2fa_started", time.time())
        if time.time() - started > 600:
            logout(request)
            return HttpResponseRedirect("/login?" + urlencode({"next": gate_url(request)}))
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
            return JsonResponse(
                {"error": "mfa_required", "redirect_url": gate_url(request)}, status=403
            )
        return HttpResponseRedirect(gate_url(request))

    def process_response(self, request, response):
        if not hasattr(request, "user") or not request.user.is_authenticated:
            return response
        if verified(request):
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
                payload["redirect_url"] = gate_url(request)
                response.content = json.dumps(payload)
        return response
