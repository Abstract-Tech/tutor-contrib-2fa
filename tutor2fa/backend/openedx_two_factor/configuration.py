"""Configure Open edX TOTP for development or production settings."""

from pathlib import Path


def configure(settings):
    settings["INSTALLED_APPS"] = list(
        dict.fromkeys(
            [
                *settings["INSTALLED_APPS"],
                "django_otp",
                "django_otp.plugins.otp_totp",
                "django_otp.plugins.otp_static",
                "two_factor",
            ]
        )
    )
    middleware = [
        item
        for item in settings["MIDDLEWARE"]
        if item
        not in (
            "django_otp.middleware.OTPMiddleware",
            "openedx_two_factor.middleware.RequireTwoFactorMiddleware",
        )
    ]
    index = next(
        i
        for i, name in enumerate(middleware)
        if name
        in (
            "django.contrib.auth.middleware.AuthenticationMiddleware",
            "openedx.core.djangoapps.cache_toolbox.middleware.CacheBackedAuthenticationMiddleware",
        )
    )
    middleware.insert(index + 1, "django_otp.middleware.OTPMiddleware")
    middleware.append("openedx_two_factor.middleware.RequireTwoFactorMiddleware")
    settings["MIDDLEWARE"] = middleware
    settings["TWO_FACTOR_PATCH_ADMIN"] = False
    settings["TWO_FACTOR_REMEMBER_COOKIE_AGE"] = 0
    settings["OTP_TOTP_THROTTLE_FACTOR"] = 1
    settings["OTP_STATIC_THROTTLE_FACTOR"] = 1
    # Open edX tracking otherwise records arbitrary POST fields, including OTPs.
    settings["TRACKING_IGNORE_URL_PATTERNS"] = list(
        dict.fromkeys(
            [
                *settings.get("TRACKING_IGNORE_URL_PATTERNS", []),
                r"^/2fa/",
            ]
        )
    )
    # Open edX uses explicit template loaders; give this app's base template priority.
    for engine in settings["TEMPLATES"]:
        if engine["BACKEND"] == "django.template.backends.django.DjangoTemplates":
            engine["DIRS"] = list(
                dict.fromkeys(
                    [
                        str(Path(__file__).parent / "templates"),
                        *engine["DIRS"],
                    ]
                )
            )
