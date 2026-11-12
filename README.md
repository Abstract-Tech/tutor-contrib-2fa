# Two-factor authentication for Tutor

Adds an authenticator-app code after Open edX password login. Includes QR setup,
one-time recovery codes, and access checks for LMS and Studio.

The plugin bundles the Open edX integration and installs
[`django-two-factor-auth`](https://github.com/jazzband/django-two-factor-auth)
1.18.1 inside the Open edX image. No manual settings patches, separate integration
repository, or extra pip requirements entries are needed.

**Review version:** not published to PyPI. Targets Tutor 22 / Open edX Verawood
and Python 3.11+. Validate your deployment on staging before enabling it for users.

## Install

Use the same Python environment as Tutor:

```bash
git clone git@github.com:Abstract-Tech/tutor-contrib-2fa.git
cd tutor-contrib-2fa
pip install .
tutor plugins enable 2fa
tutor config save
```

For local development of this plugin, use `pip install -e .` instead.
The default is `TWO_FACTOR_ENABLED=true`; enabling the plugin requires 2FA for
all browser users, including learners and administrators.

## Build and run locally

For a working Tutor development environment:

```bash
tutor images build openedx
tutor images build openedx-dev
tutor dev stop lms cms
tutor dev do two-factor-migrate
tutor dev start -d lms cms
```

Open `http://<lms-host>:8000/2fa/`. The authentication MFE, if used, must also be
running as part of your Tutor environment.

For a new Open edX environment, Tutor's normal `tutor dev launch` runs the OTP
migrations automatically after the images have been built.

## Staging and production

Configure your public LMS hostname and HTTPS, install and enable the plugin as
above, then build and activate it during a maintenance window:

```bash
tutor config save --set ENABLE_HTTPS=true
tutor images build openedx
tutor local stop lms cms lms-worker cms-worker
tutor local do two-factor-migrate
tutor local start -d lms cms lms-worker cms-worker
```

Back up the database before activation. The same settings plugin supports local,
staging and production URLs. Use the same reviewed plugin version and image on
staging and production. Full production deployment is not yet validated.

## Test the login

1. Sign in and scan the QR code with Google Authenticator or another TOTP app.
2. Enter the current six-digit code and save your recovery codes.
3. Sign out and sign in again; an OTP should be required.
4. Check that a wrong code is rejected and a recovery code cannot be reused.
5. Verify Studio/admin access and your SSO/API workflows on staging.

Keep server and phone clocks synchronized. Do not share QR codes, OTP secrets or
recovery codes.

For a repeatable HTTP check against the running LMS, run:

```bash
tutor dev exec lms ./manage.py lms two_factor_check --live
```

Use `tutor local exec` on staging. The command creates a temporary learner,
tests enrollment, OTP rejection and recovery codes, then deletes the learner
even if a check fails. Existing accounts are not used. Run it only on local or
staging environments where creating test accounts is acceptable. The configured
LMS URL must be reachable from the command's container.

## Disable

```bash
tutor config save --set TWO_FACTOR_ENABLED=false
tutor local restart lms cms lms-worker cms-worker
```

Use `tutor dev restart lms cms` for a development environment. This removes enforcement
for everyone but keeps enrolled-device records. To remove the plugin's settings
entirely, disable `2fa`, save Tutor configuration and restart application services.

## Scope

This is browser-session TOTP integration, not full tender compliance:

- FIDO2/passkeys, SMS, role-specific enforcement and invitation codes are not included.
- Non-browser token/API requests without a verified session are rejected; mobile,
  service clients and SSO need deployment-specific validation.
- First enrollment accepts an existing authenticated session. A production rollout
  needs an agreed reauthentication and account-recovery policy.
- Login finishes at the security page; course-specific login/checkout redirects
  are not preserved. Email verification and password reset remain Open edX features.

## Development and review

```bash
pip install -e '.[dev]' -e ./tutor2fa/backend
make test
make build
```

`make build` creates wheel/source distributions and checks their metadata; it does
not publish them. CI runs tests and builds artifacts only. The bundled backend is
an internal package installed into the image, not a separate PyPI release. Keep its
version in sync with `tutor2fa/__about__.py`.

Scaffold generated from
[`overhangio/cookiecutter-tutor-plugin`](https://github.com/overhangio/cookiecutter-tutor-plugin)
at commit `5d664b0f3436f375e22be789a4aaef445c3532d2`. License: AGPL-3.0-only,
following the template default; confirm release metadata and license during review.
