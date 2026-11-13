from django.apps import AppConfig


class OpenEdxTwoFactorConfig(AppConfig):
    name = "openedx_two_factor"
    verbose_name = "Open edX two-factor authentication"

    def ready(self):
        from .oauth import configure_studio_pipeline

        configure_studio_pipeline()

    plugin_app = {
        "settings_config": {
            "lms.djangoapp": {"production": {"relative_path": "settings"}},
            "cms.djangoapp": {"production": {"relative_path": "settings"}},
        },
        "url_config": {
            project: {"namespace": None, "regex": "", "relative_path": "plugin_urls"}
            for project in ("lms.djangoapp", "cms.djangoapp")
        },
    }
