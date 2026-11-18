from django.urls import include, path
from two_factor.views import QRGeneratorView

from . import views
from .recovery import recovery_codes

factor_patterns = (
    [
        path("account/two_factor/setup/", views.TwoFactorSetupView.as_view(), name="setup"),
        path("account/two_factor/qrcode/", QRGeneratorView.as_view(), name="qr"),
        path("account/two_factor/backup/tokens/", recovery_codes, name="backup_tokens"),
        path("account/two_factor/", views.home, name="profile"),
        path("account/login/", views.home, name="login"),
    ],
    "two_factor",
)
urlpatterns = [
    path("2fa/", views.home, name="openedx_2fa_home"),
    path("2fa/challenge/", views.challenge, name="openedx_2fa_challenge"),
    path("2fa/", include(factor_patterns)),
]
