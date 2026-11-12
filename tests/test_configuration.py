from copy import deepcopy

from openedx_two_factor.configuration import configure


def test_repeated_configuration_does_not_duplicate_security_components():
    settings = {
        "INSTALLED_APPS": ["django.contrib.auth"],
        "MIDDLEWARE": [
            "django.contrib.sessions.middleware.SessionMiddleware",
            "openedx.core.djangoapps.cache_toolbox.middleware.CacheBackedAuthenticationMiddleware",
        ],
        "TEMPLATES": [
            {
                "BACKEND": "django.template.backends.django.DjangoTemplates",
                "DIRS": ["/existing/templates"],
            }
        ],
    }
    configure(settings)
    expected = deepcopy(settings)
    configure(settings)
    assert settings == expected
    middleware = settings["MIDDLEWARE"]
    assert middleware[2] == "django_otp.middleware.OTPMiddleware"
    assert middleware[-1] == "openedx_two_factor.middleware.RequireTwoFactorMiddleware"
