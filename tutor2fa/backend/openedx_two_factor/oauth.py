"""Bind browser MFA to a short-lived OAuth authorization code.

The shared default cache carries proof between LMS workers. Cache loss fails
closed: the user must restart authorization. OAuth Toolkit still validates the
client credentials, redirect URI, PKCE, expiry and single-use code redemption.
"""

import hashlib
import json
import math
from urllib.parse import parse_qs, urlsplit

from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import PermissionDenied
from django.utils import timezone
from django_otp import DEVICE_ID_SESSION_KEY
from django_otp.models import Device

from .policy import requires_mfa

AUTHORIZE_PATHS = {"/oauth2/authorize", "/oauth2/authorize/"}
TOKEN_PATHS = {"/oauth2/access_token", "/oauth2/access_token/"}


def proof_key(code):
    return "openedx-2fa:oauth-code:" + hashlib.sha256(code.encode()).hexdigest()


def remember_authorization(request, response):
    """Record a browser grant and its MFA proof when the current policy requires it."""
    if request.path not in AUTHORIZE_PATHS or response.status_code != 302:
        return
    from oauth2_provider.models import get_grant_model

    codes = parse_qs(urlsplit(response.get("Location", "")).query).get("code", [])
    if len(codes) != 1:
        return
    grant = get_grant_model().objects.filter(code=codes[0], user=request.user).first()
    if grant is None or grant.is_expired():
        return
    device_id = request.session.get(DEVICE_ID_SESSION_KEY) if requires_mfa(request.user) else None
    cache.set(
        proof_key(grant.code),
        (grant.pk, grant.user_id, device_id),
        timeout=math.ceil((grant.expires - timezone.now()).total_seconds()),
    )


def verified_code_exchange(request):
    """Permit a live browser code, rechecking the current user policy."""
    if request.path not in TOKEN_PATHS or request.method != "POST":
        return False
    if request.POST.get("grant_type") != "authorization_code":
        return False
    code = request.POST.get("code", "")
    if not code or len(code) > 255:
        return False
    proof = cache.get(proof_key(code))
    if proof is None:
        return False
    from oauth2_provider.models import get_grant_model

    grant_id, user_id, device_id = proof
    grant = (
        get_grant_model()
        .objects.select_related("application", "user")
        .filter(pk=grant_id, code=code, user_id=user_id)
        .first()
    )
    if grant is None or grant.is_expired():
        return False
    if requires_mfa(grant.user):
        device = Device.from_persistent_id(device_id) if device_id else None
        if not (device and device.confirmed and device.user_id == user_id):
            return False
    else:
        device_id = None
    request._openedx_2fa_grant = (user_id, device_id, grant.application.client_id)
    return True


def token_proof_key(token):
    return "openedx-2fa:studio-token:" + hashlib.sha256(token.encode()).hexdigest()


def remember_token(request, response):
    """Allow Studio to transfer MFA to its separate session after a valid exchange."""
    proof = getattr(request, "_openedx_2fa_grant", None)
    if proof is None or response.status_code != 200:
        return
    payload = json.loads(response.content)
    token = payload.get("access_token")
    if token:
        # Only needed during the immediate SSO callback, not for API authentication.
        cache.set(token_proof_key(token), proof, timeout=60)


def restore_studio_mfa(backend, user=None, response=None, **kwargs):
    """Social-auth pipeline: bind MFA to the user before Django creates the session."""
    if not getattr(settings, "OPENEDX_2FA_ENABLED", False) or backend.name != "edx-oauth2":
        return
    token = (response or {}).get("access_token", "")
    proof = cache.get(token_proof_key(token)) if token else None
    if proof is None or user is None:
        raise PermissionDenied("Restart Studio sign-in to verify two-factor authentication.")
    user_id, device_id, client_id = proof
    if user.pk != user_id or client_id != backend.setting("KEY"):
        raise PermissionDenied("Studio sign-in has no valid two-factor verification.")
    if not requires_mfa(user):
        cache.delete(token_proof_key(token))
        return
    device = Device.from_persistent_id(device_id) if device_id else None
    if not (device and device.confirmed and device.user_id == user_id):
        raise PermissionDenied("Studio sign-in has no valid two-factor verification.")
    # django-otp's user_logged_in receiver persists this after Django login, even
    # when login replaces an existing session. Never trust client-supplied claims.
    user.otp_device = device
    cache.delete(token_proof_key(token))


def configure_studio_pipeline():
    """Install after app loading, when the social-auth strategy can be imported."""
    if not hasattr(settings, "SOCIAL_AUTH_EDX_OAUTH2_KEY"):
        return
    from auth_backends.strategies import EdxDjangoStrategy

    pipeline = getattr(settings, "SOCIAL_AUTH_EDX_OAUTH2_PIPELINE", None)
    if pipeline is None:
        pipeline = getattr(
            settings,
            "SOCIAL_AUTH_PIPELINE",
            EdxDjangoStrategy.DEFAULT_SETTINGS["SOCIAL_AUTH_PIPELINE"],
        )
    step = "openedx_two_factor.oauth.restore_studio_mfa"
    settings.SOCIAL_AUTH_EDX_OAUTH2_PIPELINE = [item for item in pipeline if item != step] + [step]
