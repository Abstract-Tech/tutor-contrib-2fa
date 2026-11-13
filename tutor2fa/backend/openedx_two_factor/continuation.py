"""Resume Open edX's existing post-login flow after the MFA step."""

from urllib.parse import urlsplit

from django.conf import settings
from django.utils.http import url_has_allowed_host_and_scheme

SESSION_KEY = "openedx_2fa_login_destination"


def safe_destination(request, destination):
    """Use Open edX's LOGIN_REDIRECT_WHITELIST policy, not a list of MFEs."""
    if not isinstance(destination, str) or any(ord(char) < 32 for char in destination):
        return False
    if not url_has_allowed_host_and_scheme(
        destination,
        allowed_hosts={request.get_host(), *getattr(settings, "LOGIN_REDIRECT_WHITELIST", [])},
        require_https=request.is_secure(),
    ):
        return False
    # Do not resume enrollment, verification or logout as a login destination.
    return not urlsplit(destination).path.startswith(("/2fa", "/logout"))


def remember_destination(request, destination):
    if safe_destination(request, destination):
        request.session[SESSION_KEY] = {"user_id": request.user.pk, "url": destination}


def take_destination(request):
    destination = request.session.pop(SESSION_KEY, {})
    if destination.get("user_id") == request.user.pk:
        url = destination.get("url")
        if safe_destination(request, url):
            return url
    return None
