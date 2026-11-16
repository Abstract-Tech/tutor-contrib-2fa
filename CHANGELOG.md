# Changelog

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
