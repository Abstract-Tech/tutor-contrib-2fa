"""Role detection, any-match enforcement and changes during active sessions."""

from itertools import combinations
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser, Group
from openedx_two_factor import policy

from . import test_flow

cookies = test_flow.cookies
device = test_flow.device
user = test_flow.user
sign_in = test_flow.sign_in

pytestmark = pytest.mark.django_db
ROLES = ["admin", "staff", "instructor", "student"]
SUBSETS = [list(c) for size in range(5) for c in combinations(ROLES, size)]


@pytest.mark.parametrize("selected", SUBSETS)
@pytest.mark.parametrize("actual", SUBSETS)
def test_any_matching_role_requires_mfa(settings, monkeypatch, selected, actual):
    user = SimpleNamespace(is_authenticated=True)
    settings.OPENEDX_2FA_REQUIRED_ROLES = selected
    monkeypatch.setattr(policy, "user_roles", lambda candidate: set(actual))
    expected = bool(set(selected) & set(actual))
    assert policy.requires_mfa(user) == expected
    assert policy.can_enroll(user) == expected


def mock_course_roles(monkeypatch, roles=(), enrolled=False):
    access, enrollment = Mock(), Mock()
    access.objects.filter.return_value.values_list.return_value = roles
    enrollment.objects.filter.return_value.exists.return_value = enrolled
    registry = Mock()
    registry.get_model.side_effect = lambda app, name: {
        "CourseAccessRole": access,
        "CourseEnrollment": enrollment,
    }[name]
    monkeypatch.setattr(policy, "apps", registry)
    return access, enrollment


@pytest.mark.parametrize("role", ["staff", "instructor"])
def test_course_or_org_staff_and_instructors_are_instructors(user, monkeypatch, role):
    user.is_staff = False
    user.save()
    access, enrollment = mock_course_roles(monkeypatch, [role])
    assert policy.user_roles(user) == {"instructor"}
    # No course/org restriction: organization-wide assignments count as well.
    access.objects.filter.assert_called_once_with(user_id=user.pk)
    enrollment.objects.filter.assert_called_once_with(user_id=user.pk, is_active=True)


@pytest.mark.parametrize("active", [False, True])
def test_only_active_enrollment_adds_student(user, monkeypatch, active):
    user.is_staff = False
    user.save()
    _, enrollment = mock_course_roles(monkeypatch, enrolled=active)
    assert policy.user_roles(user) == ({"student"} if active else set())
    enrollment.objects.filter.assert_called_once_with(user_id=user.pk, is_active=True)


def test_overlapping_roles_are_all_kept(user, monkeypatch):
    user.is_superuser = user.is_staff = True
    user.save()
    mock_course_roles(monkeypatch, ["instructor"], enrolled=True)
    assert policy.user_roles(user) == set(ROLES)


def test_custom_groups_and_course_roles_extend_policy(user, settings, monkeypatch):
    user.is_staff = False
    user.save()
    user.groups.add(Group.objects.create(name="reviewer"))
    mock_course_roles(monkeypatch, ["course_creator"])
    assert policy.user_roles(user) == {"reviewer", "course_creator"}
    for selected in (["reviewer"], ["course_creator"]):
        settings.OPENEDX_2FA_REQUIRED_ROLES = selected
        assert policy.requires_mfa(user)
    settings.OPENEDX_2FA_REQUIRED_ROLES = ["unknown"]
    assert not policy.requires_mfa(user)


def test_reserved_names_use_platform_definitions_not_group_names(user, monkeypatch):
    user.is_staff = False
    user.save()
    for name in ROLES:
        user.groups.add(Group.objects.create(name=name))
    mock_course_roles(monkeypatch, ["admin", "student"])
    assert policy.user_roles(user) == set()


def test_default_is_admin_and_staff(user, settings):
    assert policy.required_roles() == {"admin", "staff"}
    assert policy.requires_mfa(user)
    user.is_staff = False
    user.save()
    assert not policy.requires_mfa(user)
    user.is_superuser = True
    user.save()
    assert policy.requires_mfa(user)


def test_anonymous_never_requires_mfa(settings, monkeypatch):
    monkeypatch.setattr(policy, "user_roles", Mock(side_effect=AssertionError("Unexpected lookup")))
    assert not policy.requires_mfa(AnonymousUser())


def test_all_requires_mfa_for_every_authenticated_user(settings, monkeypatch):
    user = SimpleNamespace(is_authenticated=True)
    settings.OPENEDX_2FA_REQUIRED_ROLES = ["all"]
    monkeypatch.setattr(policy, "user_roles", Mock(side_effect=AssertionError("Unexpected lookup")))
    assert policy.requires_mfa(user)
    assert policy.can_enroll(user)


def test_unselected_user_keeps_normal_login_and_cannot_enroll(client, user, settings):
    settings.OPENEDX_2FA_REQUIRED_ROLES = ["admin"]
    response = sign_in(client)
    assert response.json()["redirect_url"] == "/dashboard"
    assert response.cookies["edx-jwt-cookie-header-payload"].value == "first-factor-token"
    assert client.get("/dashboard").status_code == 200
    assert client.get("/api/protected/").status_code == 200
    assert client.post("/login_refresh").status_code == 200
    assert client.get("/2fa/").status_code == 200
    for path in ("/2fa/account/two_factor/setup/", "/2fa/account/two_factor/qrcode/"):
        assert client.get(path).status_code == 403
        assert client.post(path, {}).status_code == 403


def test_existing_device_does_not_override_exclusion(client, user, device, settings):
    settings.OPENEDX_2FA_REQUIRED_ROLES = ["admin"]
    assert sign_in(client).json()["redirect_url"] == "/dashboard"
    assert client.get("/dashboard").status_code == 200
    assert client.get("/2fa/challenge/").url == "/2fa/"
    assert device.__class__.objects.filter(pk=device.pk).exists()


def test_promotion_enforces_mfa_on_existing_session(client, user, settings):
    settings.OPENEDX_2FA_REQUIRED_ROLES = ["admin"]
    sign_in(client)
    user.is_superuser = True
    user.save()
    assert client.get("/dashboard").url == "/2fa/"
    assert client.get("/api/protected/").status_code == 403
    assert client.post("/login_refresh").status_code == 401


def test_instructor_assignment_rechecked_on_next_request(client, user, settings, monkeypatch):
    settings.OPENEDX_2FA_REQUIRED_ROLES = ["instructor"]
    access, _ = mock_course_roles(monkeypatch)
    sign_in(client)
    assert client.get("/dashboard").status_code == 200
    access.objects.filter.return_value.values_list.return_value = ["staff"]
    assert client.get("/dashboard").url == "/2fa/"


def test_exemption_clears_partial_login_timeout(client, user, settings):
    sign_in(client)
    session = client.session
    session["openedx_2fa_started"] = 1
    session.save()
    settings.OPENEDX_2FA_REQUIRED_ROLES = []
    assert client.get("/dashboard").status_code == 200
    assert "openedx_2fa_started" not in client.session


def test_global_disable_overrides_roles_and_device(client, user, device, settings):
    settings.OPENEDX_2FA_ENABLED = False
    assert sign_in(client).json()["redirect_url"] == "/dashboard"
    assert not policy.requires_mfa(user)
    assert not policy.can_enroll(user)


def test_previous_exempt_session_does_not_bypass_admin_login(client, user, settings):
    settings.OPENEDX_2FA_REQUIRED_ROLES = ["admin"]
    sign_in(client)
    get_user_model().objects.create_user("admin", password="password", is_superuser=True)
    response = client.post("/login_ajax", {"username": "admin", "password": "password"})
    assert response.json()["redirect_url"] == "/2fa/"
    assert response.cookies["edx-jwt-cookie-header-payload"]["max-age"] == 0


def test_privilege_changes_ignore_cached_user_flags(user, settings):
    settings.OPENEDX_2FA_REQUIRED_ROLES = ["admin"]
    assert not policy.requires_mfa(user)
    get_user_model().objects.filter(pk=user.pk).update(is_superuser=True)
    assert not user.is_superuser  # Cached object is deliberately stale.
    assert policy.requires_mfa(user)
    get_user_model().objects.filter(pk=user.pk).update(is_superuser=False)
    assert not policy.requires_mfa(user)
