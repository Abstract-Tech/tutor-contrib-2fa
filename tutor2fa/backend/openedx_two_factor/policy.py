"""Shared role policy for LMS browser login and Studio SSO."""

from django.apps import apps
from django.conf import settings
from django.contrib.auth import get_user_model

BUILTIN_ROLES = {"admin", "staff", "instructor", "student"}


def user_roles(user):
    """Return all roles; course staff is distinct from platform staff.

    CourseAccessRole includes course-specific and organization-wide assignments.
    Custom role/group names are exact, case-sensitive names. Reserved built-in
    names always use the platform definitions below, never group membership.
    """
    if not user.is_authenticated:
        return set()
    # Open edX's authentication backend may return a cached User. Re-read
    # privilege flags so promotions take effect on an existing session.
    flags = get_user_model().objects.filter(pk=user.pk).values("is_superuser", "is_staff").first()
    if flags is None:
        return set()
    roles = set()
    if flags["is_superuser"]:
        roles.add("admin")
    if flags["is_staff"]:
        roles.add("staff")
    roles.update(set(user.groups.values_list("name", flat=True)) - BUILTIN_ROLES)
    try:
        access = apps.get_model("student", "CourseAccessRole")
        enrollment = apps.get_model("student", "CourseEnrollment")
    except LookupError:
        # The standalone Django test/demo has no Open edX student app.
        return roles
    course_roles = set(access.objects.filter(user_id=user.pk).values_list("role", flat=True))
    if course_roles & {"instructor", "staff"}:
        roles.add("instructor")
    roles.update(course_roles - BUILTIN_ROLES)
    if enrollment.objects.filter(user_id=user.pk, is_active=True).exists():
        roles.add("student")
    return roles


def required_roles():
    return set(getattr(settings, "OPENEDX_2FA_REQUIRED_ROLES", ["admin", "staff"]))


def requires_mfa(user):
    if not getattr(settings, "OPENEDX_2FA_ENABLED", False) or not user.is_authenticated:
        return False
    selected = required_roles()
    if "all" in selected:
        return True
    return bool(selected and selected.intersection(user_roles(user)))


def can_enroll(user):
    return requires_mfa(user)
