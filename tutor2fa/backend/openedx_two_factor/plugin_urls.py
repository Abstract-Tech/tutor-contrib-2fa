from django.conf import settings

urlpatterns = []
if getattr(settings, "OPENEDX_2FA_ENABLED", False):
    from . import urls

    urlpatterns = urls.urlpatterns
