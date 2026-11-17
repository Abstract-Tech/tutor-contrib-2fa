from io import StringIO

import pytest
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django_otp.plugins.otp_totp.models import TOTPDevice
from openedx_two_factor import verification

pytestmark = pytest.mark.django_db


def test_live_check_requires_explicit_flag():
    with pytest.raises(CommandError, match="Pass --live"):
        call_command("two_factor_check")
    assert not get_user_model().objects.exists()


def test_live_check_requires_enabled_integration(settings):
    settings.OPENEDX_2FA_ENABLED = False
    with pytest.raises(CommandError, match="2FA must be enabled"):
        call_command("two_factor_check", live=True)
    assert not get_user_model().objects.exists()


def test_live_check_requires_valid_lms_url(settings):
    settings.OPENEDX_2FA_LMS_URL = ""
    with pytest.raises(CommandError, match="valid OPENEDX_2FA_LMS_URL"):
        call_command("two_factor_check", live=True)
    assert not get_user_model().objects.exists()


def test_profile_creation_failure_removes_temporary_account(monkeypatch):
    def fail(user):
        assert get_user_model().objects.filter(pk=user.pk).exists()
        raise RuntimeError("profile creation failed")

    monkeypatch.setattr(verification, "create_profile", fail)
    with pytest.raises(RuntimeError, match="profile creation failed"):
        with verification.temporary_account():
            pytest.fail("Profile creation should fail before yielding the account")
    assert not get_user_model().objects.exists()


def test_failed_http_check_removes_only_temporary_account(monkeypatch):
    existing = get_user_model().objects.create_user("existing")
    device = TOTPDevice.objects.create(user=existing, name="default")
    monkeypatch.setattr(verification, "create_profile", lambda user: None)

    def fail(self):
        TOTPDevice.objects.create(user=self.user, name="default")
        raise verification.VerificationError("enrollment failed")

    monkeypatch.setattr(verification.LoginVerification, "enroll", fail)
    with pytest.raises(verification.VerificationError, match="enrollment failed"):
        verification.verify_login("https://learn.example.test", lambda message: None)
    assert list(get_user_model().objects.values_list("pk", flat=True)) == [existing.pk]
    assert list(TOTPDevice.objects.values_list("pk", flat=True)) == [device.pk]


def test_command_runs_verifier_with_configured_url(monkeypatch, settings):
    from openedx_two_factor.management.commands import two_factor_check

    settings.OPENEDX_2FA_LMS_URL = "https://learn.example.test"
    calls = []

    def verify(url, report):
        calls.append(url)
        report("PASS: verified")

    monkeypatch.setattr(two_factor_check, "verify_login", verify)
    output = StringIO()
    call_command("two_factor_check", live=True, stdout=output)
    assert calls == [settings.OPENEDX_2FA_LMS_URL]
    assert "PASS: verified" in output.getvalue()


def test_live_check_refuses_exempt_staff_and_cleans_up(monkeypatch, settings):
    settings.OPENEDX_2FA_REQUIRED_ROLES = ["admin"]
    monkeypatch.setattr(verification, "create_profile", lambda user: None)
    with pytest.raises(verification.VerificationError, match="requires staff"):
        verification.verify_login("https://learn.example.test", lambda message: None)
    assert not get_user_model().objects.exists()
