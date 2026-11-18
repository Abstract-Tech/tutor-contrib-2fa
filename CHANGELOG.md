# Changelog

## 1.0.2 — 2026-11-18

- Require recovery-code generation and successful copying after initial 2FA setup.
- Preserve incomplete recovery setup across sessions and protect access until completion.
- Allow verified users to manage and replace recovery codes, invalidating the previous set.
- Improve recovery-page controls, clipboard feedback and accessibility.
- Add the recovery-state migration and include it in Tutor initialization.
- Remove the completed one-off 1.0.1 publishing workflow.

## 1.0.1 — 2026-11-17

- Add translations for the bundled two-factor-authentication templates and plugin pages.
- Add a responsive shared two-factor UI, including RTL support and validation-error styling.
- Add an inactive-policy page for users who are exempt from MFA enforcement.

## 0.1.0 — Initial package-index release (testing)

- Prepare the existing plugin for its first TestPyPI release under Abstract-Tech.
- Add a tag-triggered Trusted Publisher workflow with version validation, tests and an installation check.
- Keep the earlier `v1.0.0` Git tag unchanged; it was never published to PyPI.

## 1.0.0 — 2026-11-16

- Generate the Tutor plugin scaffold from overhangio/cookiecutter-tutor-plugin.
- Bundle the Django integration and install it during the Open edX image build.
- Configure LMS and Studio through Open edX settings hooks.
- Support configurable authentication library versions and 2FA enforcement.
- Run OTP migrations through `tutor local do init -l 2fa` (or `tutor dev`).
- Include TOTP enrollment, one-time recovery codes and session/access checks.
- Support Studio OAuth MFA handoff and preserve Open edX login redirects.
- Handle MFE bootstrap and JWT refresh alongside MFA verification.
- Include regression tests and installation documentation.

Production validation and feature limitations are documented in the README.
