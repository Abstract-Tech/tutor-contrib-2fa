"""Exercise Tutor through its installed entry point, isolated from host config."""

import json
import os
import subprocess
import sys
from pathlib import Path

from jinja2 import Environment

from tutor2fa import plugin


def tutor(root, *args, check=True, capture_tasks=False):
    env = dict(os.environ, TUTOR_ROOT=str(root), TUTOR_PLUGINS_ROOT=str(root / "plugins"))
    # A parent shell may already have selected plugins for another project.
    env.pop("TUTOR_PLUGINS", None)
    env.pop("TUTOR_APP", None)
    command = (
        [sys.executable, "-m", "tests.capture_init"]
        if capture_tasks
        else [str(Path(sys.executable).with_name("tutor"))]
    )
    return subprocess.run(
        [*command, *args],
        env=env,
        capture_output=True,
        text=True,
        check=check,
    )


def test_installed_plugin_renders_images_settings_and_migration_job(tmp_path):
    assert "2fa" in tutor(tmp_path, "plugins", "list").stdout
    tutor(tmp_path, "plugins", "enable", "2fa")
    tutor(
        tmp_path,
        "config",
        "save",
        "--set",
        "LMS_HOST=learn.example.test",
        "--set",
        "ENABLE_HTTPS=true",
    )
    env = tmp_path / "env"
    dockerfile = (env / "build/openedx/Dockerfile").read_text()
    assert "COPY two-factor /openedx/two-factor" in dockerfile
    assert (
        'RUN pip install "django-two-factor-auth[phonenumberslite]==1.18.1" /openedx/two-factor'
        in dockerfile
    )
    backend = env / "build/openedx/two-factor"
    assert (backend / "pyproject.toml").is_file()
    template = (backend / "openedx_two_factor/templates/openedx_two_factor/home.html").read_text()
    assert "{{ request.user.username }}" in template  # Not rendered by Tutor.
    assert "{% url 'two_factor:backup_tokens' %}" in template
    for service in ("lms", "cms"):
        for mode in ("development", "production"):
            source = (env / f"apps/openedx/settings/{service}/{mode}.py").read_text()
            compile(source, "<settings>", "exec")
            assert "OPENEDX_2FA_ENABLED = True" in source
            assert "configure_two_factor" not in source
            assert "OPENEDX_2FA_LMS_URL = LMS_ROOT_URL" in source
    for mode in ("local", "dev"):
        assert "two-factor-migrate" not in tutor(tmp_path, mode, "do", "--help").stdout
        result = tutor(tmp_path, mode, "do", "init", "-l", "2fa", capture_tasks=True)
        tasks = [
            json.loads(line.removeprefix("TASK:"))
            for line in result.stdout.splitlines()
            if line.startswith("TASK:")
        ]
        assert tasks == [
            [
                "lms",
                "set -e\n./manage.py lms migrate otp_totp --noinput\n./manage.py lms migrate otp_static --noinput",
            ]
        ]

    tutor(tmp_path, "config", "save", "--set", "ENABLE_2FA=false")
    source = (env / "apps/openedx/settings/lms/production.py").read_text()
    result = tutor(tmp_path, "local", "do", "init", "-l", "2fa", capture_tasks=True)
    tasks = [
        json.loads(line.removeprefix("TASK:"))
        for line in result.stdout.splitlines()
        if line.startswith("TASK:")
    ]
    assert tasks == [["lms", ""]]
    assert "OPENEDX_2FA_ENABLED = False" in source
    assert "configure_two_factor" not in source
    tutor(tmp_path, "config", "save", "--set", "TWO_FACTOR_AUTH_VERSION=1.18.0")
    dockerfile = (env / "build/openedx/Dockerfile").read_text()
    assert "django-two-factor-auth[phonenumberslite]==1.18.0" in dockerfile
    assert "django-two-factor-auth[phonenumberslite]==1.18.1" not in dockerfile
    assert "==1.18.1" not in (backend / "pyproject.toml").read_text()
    # Once disabled entirely, neither installation nor settings patches remain.
    tutor(tmp_path, "plugins", "disable", "2fa")
    tutor(tmp_path, "config", "save")
    assert "/openedx/two-factor" not in (env / "build/openedx/Dockerfile").read_text()


def test_invalid_enable_setting_rejected(tmp_path):
    tutor(tmp_path, "plugins", "enable", "2fa")
    result = tutor(tmp_path, "config", "save", "--set", "ENABLE_2FA=not-a-bool", check=False)
    assert result.returncode != 0
    assert "ENABLE_2FA must be true or false" in result.stdout + result.stderr


def test_settings_use_public_or_development_lms_url():
    for mode, url in [
        ("production", "https://learn.example.test"),
        ("development", "http://local.example.test:8000"),
    ]:
        for service in ("lms", "cms"):
            _, patch = plugin.patch(f"openedx-{service}-{mode}-settings")
            source = (
                Environment()
                .from_string(patch)
                .render(
                    ENABLE_2FA=True, TWO_FACTOR_AUTHENTICATION_REQUIRED_ROLES=["admin", "staff"]
                )
            )
            settings = {
                "LMS_ROOT_URL": url,
                "INSTALLED_APPS": [],
                "MIDDLEWARE": ["django.contrib.auth.middleware.AuthenticationMiddleware"],
                "TEMPLATES": [],
            }
            exec(source, settings)
            assert settings["OPENEDX_2FA_ENABLED"] is True
            assert settings["OPENEDX_2FA_LMS_URL"] == url


def test_migration_job_is_guarded_and_contains_both_apps():
    source = Environment().from_string(plugin.MIGRATE)
    assert source.render(ENABLE_2FA=False).strip() == ""
    enabled = source.render(
        ENABLE_2FA=True, TWO_FACTOR_AUTHENTICATION_REQUIRED_ROLES=["admin", "staff"]
    )
    assert "migrate otp_totp --noinput" in enabled
    assert "migrate otp_static --noinput" in enabled


def test_distribution_versions_match():
    import tomllib

    from tutor2fa.__about__ import __version__

    metadata = tomllib.loads((Path(plugin.__file__).parent / "backend/pyproject.toml").read_text())
    assert metadata["project"]["version"] == __version__


def test_url_registration_respects_enable_setting():
    import importlib

    from django.test import override_settings
    from openedx_two_factor import plugin_urls

    try:
        with override_settings(OPENEDX_2FA_ENABLED=False):
            assert importlib.reload(plugin_urls).urlpatterns == []
        with override_settings(OPENEDX_2FA_ENABLED=True):
            assert len(importlib.reload(plugin_urls).urlpatterns) > 0
    finally:
        importlib.reload(plugin_urls)


def test_invalid_library_version_rejected(tmp_path):
    tutor(tmp_path, "plugins", "enable", "2fa")
    result = tutor(
        tmp_path,
        "config",
        "save",
        "--set",
        "TWO_FACTOR_AUTH_VERSION=1.18.1; echo unsafe",
        check=False,
    )
    assert result.returncode != 0
    assert (
        "TWO_FACTOR_AUTH_VERSION must be a valid package version" in result.stdout + result.stderr
    )


def test_required_roles_default_and_validation():
    import pytest
    from tutor.exceptions import TutorError

    plugin.validate_config({})
    for roles in ([], ["admin", "staff"], ["Reviewer"], ["staff", "staff"]):
        plugin.validate_config({"TWO_FACTOR_AUTHENTICATION_REQUIRED_ROLES": roles})
    for roles in ("admin", None, True, [1], [""], [" "], [" staff"], [{}]):
        with pytest.raises(TutorError, match="TWO_FACTOR_AUTHENTICATION_REQUIRED_ROLES"):
            plugin.validate_config({"TWO_FACTOR_AUTHENTICATION_REQUIRED_ROLES": roles})


def test_custom_roles_render_as_data_for_both_services(tmp_path):
    tutor(tmp_path, "plugins", "enable", "2fa")
    tutor(
        tmp_path,
        "config",
        "save",
        "--set",
        'TWO_FACTOR_AUTHENTICATION_REQUIRED_ROLES=["instructor", "reviewer"]',
    )
    for service in ("lms", "cms"):
        for mode in ("development", "production"):
            source = (tmp_path / f"env/apps/openedx/settings/{service}/{mode}.py").read_text()
            compile(source, "<settings>", "exec")
            assert "OPENEDX_2FA_REQUIRED_ROLES = ['instructor', 'reviewer']" in source


def test_old_enable_key_requires_explicit_migration():
    import pytest
    from tutor.exceptions import TutorError

    for old in ("TWO_FACTOR_AUTH_ENABLED", "TWO_FACTOR_ENABLED"):
        with pytest.raises(TutorError, match=f"Replace {old} with ENABLE_2FA"):
            plugin.validate_config({old: False})
