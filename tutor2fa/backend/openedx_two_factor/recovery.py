"""Manage recovery codes within an already 2FA-verified session."""

import uuid

from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.core import signing
from django.db import transaction
from django.http import HttpResponseForbidden, JsonResponse
from django.shortcuts import render
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_http_methods
from django_otp.plugins.otp_static.models import StaticDevice, StaticToken

from .middleware import verified
from .models import RecoverySetup
from .policy import requires_mfa


class RecoveryActionForm(forms.Form):
    action = forms.ChoiceField(
        choices=[("generate", "generate"), ("acknowledge", "acknowledge")],
        widget=forms.HiddenInput,
    )
    receipt = forms.CharField(required=False, widget=forms.HiddenInput)
    confirm = forms.BooleanField(
        required=False,
        label=_(
            "Replace all existing recovery codes. The old codes will stop working immediately."
        ),
    )


@login_required
@never_cache
@csrf_protect
@require_http_methods(["GET", "POST"])
def recovery_codes(request):
    if not requires_mfa(request.user) or not verified(request):
        return HttpResponseForbidden()
    codes = []
    status = 200
    form = RecoveryActionForm(request.POST if request.method == "POST" else None)
    with transaction.atomic():
        # Serialize recovery-code changes for this account.
        get_user_model().objects.select_for_update().get(pk=request.user.pk)
        setup = RecoverySetup.objects.get_or_create(user=request.user)[0]
        backups = StaticDevice.objects.filter(user=request.user, name="backup")
        exists = backups.exists()
        count = StaticToken.objects.filter(device__in=backups).count()
        if request.method == "POST":
            if form.is_valid():
                action = form.cleaned_data["action"]
                if action == "acknowledge":
                    try:
                        receipt = signing.loads(
                            form.cleaned_data["receipt"], salt="2fa-recovery-save", max_age=86400
                        )
                    except signing.BadSignature:
                        return JsonResponse({"error": "invalid_receipt"}, status=400)
                    if (
                        receipt != {"user": request.user.pk, "revision": str(setup.revision)}
                        or not count
                    ):
                        return JsonResponse({"error": "stale_recovery_codes"}, status=409)
                    setup.saved_at = timezone.now()
                    setup.save(update_fields=["saved_at"])
                    return JsonResponse({"saved": True})
                if action == "generate" and exists and not form.cleaned_data["confirm"]:
                    form.add_error(
                        "confirm", _("Confirm that you want to replace your recovery codes.")
                    )
                elif action == "generate":
                    # Revoke every old backup code, even if legacy duplicate devices exist.
                    StaticToken.objects.filter(device__in=backups).delete()
                    backup = backups.order_by("pk").first()
                    if backup is None:
                        backup = StaticDevice.objects.create(user=request.user, name="backup")
                    codes = [StaticToken.random_token() for _ in range(10)]
                    StaticToken.objects.bulk_create(
                        [StaticToken(device=backup, token=code) for code in codes]
                    )
                    exists, count = True, len(codes)
                    setup.revision = uuid.uuid4()
                    setup.saved_at = None
                    setup.save(update_fields=["revision", "saved_at"])
                if not form.errors:
                    form = RecoveryActionForm()
            if form.errors:
                status = 400
        if not codes:
            codes = list(
                StaticToken.objects.filter(device__in=backups)
                .order_by("pk")
                .values_list("token", flat=True)
            )
        receipt = (
            signing.dumps(
                {"user": request.user.pk, "revision": str(setup.revision)}, salt="2fa-recovery-save"
            )
            if codes
            else ""
        )
        # Render within the transaction: a template error must not revoke codes.
        response = render(
            request,
            "openedx_two_factor/recovery.html",
            {
                "codes": codes,
                "issued": exists,
                "form": form,
                "saved": setup.saved_at is not None,
                "receipt": receipt,
            },
            status=status,
        )
    response["Referrer-Policy"] = "same-origin"
    return response
