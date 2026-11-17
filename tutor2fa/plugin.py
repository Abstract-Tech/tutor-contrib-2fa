"""Install and configure the bundled Open edX two-factor integration."""

import shutil
from importlib.resources import files
from pathlib import Path

from packaging.version import InvalidVersion, Version
from tutor import hooks
from tutor.exceptions import TutorError

from .__about__ import __version__

hooks.Filters.CONFIG_DEFAULTS.add_items(
    [
        ("TWO_FACTOR_VERSION", __version__),
        ("ENABLE_2FA", True),
        ("TWO_FACTOR_AUTHENTICATION_REQUIRED_ROLES", ["admin", "staff"]),
        ("TWO_FACTOR_AUTH_VERSION", "1.18.1"),
    ]
)


@hooks.Actions.CONFIG_LOADED.add()
def validate_config(config):
    for old_name in ("TWO_FACTOR_AUTH_ENABLED", "TWO_FACTOR_ENABLED"):
        if old_name in config:
            raise TutorError(
                f"Replace {old_name} with ENABLE_2FA in config.yml, preserving its value."
            )
    if not isinstance(config.get("ENABLE_2FA", True), bool):
        raise TutorError("ENABLE_2FA must be true or false.")
    roles = config.get("TWO_FACTOR_AUTHENTICATION_REQUIRED_ROLES", ["admin", "staff"])
    if not isinstance(roles, list) or any(
        not isinstance(role, str) or not role.strip() or role != role.strip() for role in roles
    ):
        raise TutorError(
            "TWO_FACTOR_AUTHENTICATION_REQUIRED_ROLES must be a list of non-empty, "
            "role names without surrounding whitespace."
        )

    try:
        Version(str(config.get("TWO_FACTOR_AUTH_VERSION", "1.18.1")))
    except InvalidVersion as exc:
        raise TutorError("TWO_FACTOR_AUTH_VERSION must be a valid package version.") from exc


@hooks.Actions.ENV_SAVED.add()
def stage_backend(root, config):
    """Copy raw package files: Django templates must not be rendered by Tutor."""
    target = Path(root) / "build" / "openedx" / "two-factor"
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(
        str(files("tutor2fa") / "backend"),
        target,
        ignore=shutil.ignore_patterns(
            "__pycache__", "*.pyc", "*.egg-info", "build", "dist", ".pytest_cache"
        ),
    )


def patch(name):
    return (name, (files("tutor2fa") / "patches" / name).read_text(encoding="utf-8"))


# Separate registrations keep each supported environment explicit.
hooks.Filters.ENV_PATCHES.add_item(patch("openedx-dockerfile-post-python-requirements"))
hooks.Filters.ENV_PATCHES.add_item(patch("openedx-lms-development-settings"))
hooks.Filters.ENV_PATCHES.add_item(patch("openedx-cms-development-settings"))
hooks.Filters.ENV_PATCHES.add_item(patch("openedx-lms-production-settings"))
hooks.Filters.ENV_PATCHES.add_item(patch("openedx-cms-production-settings"))

MIGRATE = """
{% if ENABLE_2FA %}
set -e
./manage.py lms migrate otp_totp --noinput
./manage.py lms migrate otp_static --noinput
{% endif %}
"""

# Tutor loads this registration in the 2fa plugin context, so both regular init
# and `tutor local do init -l 2fa` select these migrations.
hooks.Filters.CLI_DO_INIT_TASKS.add_item(("lms", MIGRATE))
