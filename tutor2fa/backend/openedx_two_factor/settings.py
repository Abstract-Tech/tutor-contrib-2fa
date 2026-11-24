"""Open edX loads this module through the Django app settings entry point."""

from .configuration import configure


def plugin_settings(settings):
    """Register OTP components; Tutor supplies the final enable flag and LMS URL."""
    # Tutor development settings also inherit Open edX production settings.
    # At this hook, Studio has resolved its Derived template directory values.
    settings.OPENEDX_2FA_ENABLED = False
    settings.OPENEDX_2FA_REQUIRED_ROLES = ["admin", "staff"]
    settings.OPENEDX_2FA_BEARER_APPLICATIONS = []
    settings.OPENEDX_2FA_TOKEN_PATHS = []
    configure(vars(settings))
