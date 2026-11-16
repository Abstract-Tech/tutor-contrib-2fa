# Two-factor authentication plugin for [Tutor](https://docs.tutor.edly.io)

Adds authenticator-app 2FA to Open edX login, with QR enrollment, one-time
recovery codes, and access checks for LMS and Studio. The plugin installs
[`django-two-factor-auth`](https://github.com/jazzband/django-two-factor-auth)
and the bundled Open edX integration in the Open edX image.

Targets Tutor 22 / Open edX Verawood. Version 0.1.0 is being prepared for TestPyPI; it is not published to production PyPI.

## Installation

Install in the same Python environment as Tutor:

```bash
pip install git+https://github.com/Abstract-Tech/tutor-contrib-2fa
```

No separate integration package or manual settings plugin is needed.

## Usage

```bash
tutor plugins enable 2fa
tutor config save
tutor images build openedx
```

For an existing development environment:

```bash
tutor images build openedx-dev
tutor dev stop lms cms
tutor dev do init -l 2fa
tutor dev start -d lms cms
```

Open `http://<lms-host>:8000/2fa/`. Keep the authentication MFE running if your
installation uses it. For a new environment, use `tutor dev launch` after building;
the normal initialization runs the OTP migrations automatically.

For staging or production, configure your public hostnames and HTTPS first.
Back up the database and activate during a maintenance window:

```bash
tutor config save --set ENABLE_HTTPS=true
tutor local stop lms cms lms-worker cms-worker
tutor local do init -l 2fa
tutor local start -d lms cms lms-worker cms-worker
```

Use the same reviewed plugin version and image on staging and production.
Full production deployment has not yet been validated.

### Test the login

1. Sign in, scan the QR code with an authenticator app, and enter its current code.
2. Save the recovery codes, sign out, and sign in again; an OTP should be required.
3. Check that a wrong OTP is rejected and a recovery code works only once.
4. Check Studio/admin access and your SSO/API workflows on staging.

Keep phone and server clocks synchronized. Keep QR secrets and recovery codes private.

For an automated check on local or staging:

```bash
tutor dev exec lms ./manage.py lms two_factor_check --live
```

Use `tutor local exec` on staging. The command creates a temporary learner,
checks login/enrollment/recovery, and deletes that learner even if a check fails.
The configured LMS URL must be reachable from the command's container.

## Configuration

Set these values with `tutor config save --set NAME=value`:

| Setting | Default | Description |
| --- | --- | --- |
| `TWO_FACTOR_AUTH_ENABLED` | `true` | Require 2FA for all browser users, including learners and administrators. |
| `TWO_FACTOR_AUTH_VERSION` | `1.18.1` | Version of `django-two-factor-auth` installed when building the Open edX image. |

To disable enforcement while keeping enrolled devices and recovery codes:

```bash
tutor config save --set TWO_FACTOR_AUTH_ENABLED=false
tutor local restart lms cms lms-worker cms-worker
```

For development, use `tutor dev restart lms cms`. Set the value to `true` and
restart the same services to enable enforcement again. No image rebuild is needed
for this setting. Disabling the Tutor plugin also removes enforcement after saving
configuration and restarting services.

When upgrading from the initial review version, replace `TWO_FACTOR_ENABLED` in
Tutor's `config.yml` with `TWO_FACTOR_AUTH_ENABLED`, preserving its value. The old
name is no longer read; without the new setting, enforcement defaults to `true`.

To upgrade the authenticator library without changing the plugin code:

```bash
tutor config save --set TWO_FACTOR_AUTH_VERSION=<version>
tutor images build openedx
```

Replace `<version>` with the exact release you want. For development, also rebuild
`openedx-dev`. Then repeat the stop, migrate and start commands above for your
environment. Test the selected version on staging before production use.

### Scope

- Browser-session TOTP only; FIDO2/passkeys, role-specific enforcement and invitation codes are not included.
- Studio SSO supports authorization codes issued after LMS MFA. OAuth Toolkit still
  validates client credentials, redirect URIs, PKCE and code expiry/replay. Studio
  receives the verified device through a short-lived server-side proof and records
  it in its own session; browser cookies are not forwarded to the token endpoint.
- LMS workers and Studio must use the same shared default Django cache (Tutor's
  Redis default cache). Authorization proof expires with the code; Studio's session
  handoff expires after 60 seconds. Cache loss fails closed: restart Studio sign-in.
  Codes issued before this update must also be replaced by restarting sign-in.
- Other non-browser API/token requests without a verified session are rejected;
  mobile, service clients and refresh-token grants need separate validation.
- First enrollment accepts an existing authenticated session; agree a reauthentication and recovery policy before production rollout.
- MFA is a step in the existing browser login: after verification the plugin
  resumes the platform-selected destination, including `finish_auth`, course links
  and Studio authorization. Destinations use Open edX's `LOGIN_REDIRECT_WHITELIST`
  and are bound to the signing-in user. Configure approved MFE hosts there as usual.
- A verified LMS session keeps using the normal login redirects and JWT refresh;
  moving between MFEs does not require another OTP. Studio's separate session is
  verified through LMS OAuth. This is SSO, not a shared cookie across arbitrary
  domains, and does not change Open edX's session expiry or logout semantics.
- Email verification and password reset remain Open edX features.

## Development

```bash
git clone git@github.com:Abstract-Tech/tutor-contrib-2fa.git
cd tutor-contrib-2fa
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]' -e ./tutor2fa/backend
make test
make build
```

`make build` creates and checks distributions; it does not publish them. The
backend is bundled with this plugin, not published separately. Keep its version
in sync with `tutor2fa/__about__.py`.

Scaffold generated from
[`overhangio/cookiecutter-tutor-plugin`](https://github.com/overhangio/cookiecutter-tutor-plugin)
at commit `5d664b0f3436f375e22be789a4aaef445c3532d2`.

## TestPyPI publishing

The first package-index version is `0.1.0`. The earlier `v1.0.0` Git tag remains
unchanged; it was not a PyPI release.

Using the TestPyPI account that should own this package, add a pending publisher
at <https://test.pypi.org/manage/account/publishing/>:

| Field | Value |
| --- | --- |
| Project name | `tutor-contrib-2fa` |
| GitHub owner | `Abstract-Tech` |
| Repository | `tutor-contrib-2fa` |
| Workflow | `release.yml` |
| Environment | `testpypi` |

The GitHub owner does not automatically assign PyPI account or organization
ownership. Configure the publisher from the intended owning account.

Push a version tag matching both package versions to trigger publishing:

```bash
git tag -a v0.1.0 -m "Release 0.1.0"
git push origin v0.1.0
```

Create the tag only once. For later releases, update both package versions and use
a new matching tag. The workflow checks the versions, tests and builds the package,
publishes with OIDC, then checks installation from TestPyPI. It has no production
PyPI publishing job. Configure the TestPyPI publisher before pushing the tag.

To test installation manually in a fresh virtual environment:

```bash
python -m pip install 'tutor>=22,<23' 'packaging>=23'
python -m pip install --no-deps --index-url https://test.pypi.org/simple/ tutor-contrib-2fa==0.1.0
python -m pip check
tutor plugins list
```

Dependencies come from PyPI; only this plugin comes from TestPyPI. Do this after
the upload succeeds. TestPyPI accounts and publishers are separate from PyPI.
An already uploaded version cannot be overwritten; use a new version for changes.

## License

This software is licensed under the terms of the AGPLv3 (AGPL-3.0-only).
