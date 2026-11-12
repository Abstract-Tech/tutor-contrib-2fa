"""Install and configure the bundled Open edX two-factor integration."""

import shutil
from importlib.resources import files
from pathlib import Path

import click
from packaging.version import InvalidVersion, Version
from tutor import hooks
from tutor.exceptions import TutorError

from .__about__ import __version__

hooks.Filters.CONFIG_DEFAULTS.add_items(
    [
        ("TWO_FACTOR_VERSION", __version__),
        ("TWO_FACTOR_AUTH_ENABLED", True),
        ("TWO_FACTOR_AUTH_VERSION", "1.18.1"),
    ]
)


@hooks.Actions.CONFIG_LOADED.add()
def validate_config(config):
    if not isinstance(config.get("TWO_FACTOR_AUTH_ENABLED", True), bool):
        raise TutorError("TWO_FACTOR_AUTH_ENABLED must be true or false.")

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
{% if TWO_FACTOR_AUTH_ENABLED %}
set -e
./manage.py lms migrate otp_totp --noinput
./manage.py lms migrate otp_static --noinput
{% endif %}
"""

# Included automatically in Tutor's standard launch/init workflow.
hooks.Filters.CLI_DO_INIT_TASKS.add_item(("lms", MIGRATE))


@click.command(name="two-factor-migrate")
def migrate():
    """Create the OTP tables after building the Open edX image."""
    return [("lms", MIGRATE)]


hooks.Filters.CLI_DO_COMMANDS.add_item(migrate)
