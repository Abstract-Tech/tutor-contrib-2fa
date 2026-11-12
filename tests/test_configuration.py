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


def test_openedx_settings_entry_points_register_components_without_enabling():
    from types import SimpleNamespace

    from openedx_two_factor.apps import OpenEdxTwoFactorConfig
    from openedx_two_factor.settings import plugin_settings

    for service in ("lms.djangoapp", "cms.djangoapp"):
        assert (
            OpenEdxTwoFactorConfig.plugin_app["settings_config"][service]["production"][
                "relative_path"
            ]
            == "settings"
        )
        settings = SimpleNamespace(
            INSTALLED_APPS=[],
            MIDDLEWARE=["django.contrib.auth.middleware.AuthenticationMiddleware"],
            TEMPLATES=[],
            LOGIN_REDIRECT_URL="/dashboard",
        )
        plugin_settings(settings)
        assert settings.OPENEDX_2FA_ENABLED is False
        assert "django_otp.plugins.otp_totp" in settings.INSTALLED_APPS
        assert "openedx_two_factor.middleware.RequireTwoFactorMiddleware" in settings.MIDDLEWARE
        assert settings.LOGIN_REDIRECT_URL == "/dashboard"
