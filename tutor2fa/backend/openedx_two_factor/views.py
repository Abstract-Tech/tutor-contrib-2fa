from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.debug import sensitive_post_parameters
from django_otp import login as otp_login
from django_otp.plugins.otp_static.models import StaticDevice
from two_factor.forms import AuthenticationTokenForm, BackupTokenForm
from two_factor.utils import default_device
from two_factor.views import SetupView

from .middleware import verified


def finish(request, response):
    from openedx.core.djangoapps.user_authn.cookies import set_logged_in_cookies

    request.session.pop("openedx_2fa_started", None)
    request.session.cycle_key()
    return set_logged_in_cookies(request, response, request.user)


@login_required
@never_cache
def home(request):
    if not verified(request):
        return redirect(
            "openedx_2fa_challenge" if default_device(request.user) else "two_factor:setup"
        )
    return finish(request, render(request, "openedx_two_factor/home.html"))


@login_required
@never_cache
@csrf_protect
@sensitive_post_parameters("otp_token")
def challenge(request):
    if verified(request):
        return redirect("openedx_2fa_home")
    device = default_device(request.user)
    if not device:
        return redirect("two_factor:setup")
    recovery = request.GET.get("recovery") == "1"
    if recovery:
        device = StaticDevice.objects.filter(user=request.user, name="backup").first()
    form_class = BackupTokenForm if recovery else AuthenticationTokenForm
    form = form_class(
        user=request.user,
        initial_device=device,
        data=request.POST if request.method == "POST" else None,
    )
    if request.method == "POST" and form.is_valid():
        otp_login(request, request.user.otp_device)
        return finish(request, redirect("openedx_2fa_home"))
    return render(
        request, "openedx_two_factor/challenge.html", {"form": form, "recovery": recovery}
    )


class TwoFactorSetupView(SetupView):
    def get_success_url(self):
        return "/2fa/"
