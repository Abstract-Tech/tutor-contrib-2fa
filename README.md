# Two-factor authentication plugin for [Tutor](https://docs.tutor.edly.io)

Adds authenticator-app 2FA to Open edX login, with QR enrollment, one-time
recovery codes, and access checks for LMS and Studio. The plugin installs
[`django-two-factor-auth`](https://github.com/jazzband/django-two-factor-auth)
and the bundled Open edX integration in the Open edX image.

Targets Tutor 22 / Open edX Verawood. The role configuration below describes the
current source version; it is not included in the published 0.1.0 release.

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

1. Sign in as a user in a required role (admin or staff by default), scan the QR code with an authenticator app, and enter its current code.
2. Save the recovery codes, sign out, and sign in again; an OTP should be required.
3. Check that a wrong OTP is rejected and a recovery code works only once.
4. Sign in as an ordinary user without a required role; login should not ask for 2FA.
5. Check Studio/admin access and your SSO/API workflows on staging.

Keep phone and server clocks synchronized. Keep QR secrets and recovery codes private.

For an automated check on local or staging:

```bash
tutor dev exec lms ./manage.py lms two_factor_check --live
```

Use `tutor local exec` on staging. The command creates a temporary **platform staff account**,
checks login/enrollment/recovery, and deletes it even if a check fails.
This automated check requires `staff` in the required roles list.
The configured LMS URL must be reachable from the command's container.

## Configuration

Use these two settings in Tutor's `config.yml`:

```yaml
ENABLE_2FA: true
TWO_FACTOR_AUTHENTICATION_REQUIRED_ROLES:
  - admin
  - staff
```

These are the defaults. Add `instructor` and/or `student` to require 2FA for them too.

| Role | Who matches |
| --- | --- |
| `admin` | Superusers (`is_superuser`). |
| `staff` | Platform staff (`is_staff`). |
| `instructor` | Users with course or organization `instructor` or `staff` access. |
| `student` | Users with at least one active course enrollment. |
| Custom name | An existing course/organization role or Django group with that exact name. |

A match on **any** role requires setup and 2FA at sign-in. These roles apply across
the account, not just while visiting a particular course. A newly registered user
without an active enrollment does not yet match `student`.

No match means normal login, even if the user previously enrolled an authenticator.
Existing devices and recovery codes are kept, but new enrollment is unavailable
for exempt users. An empty list (`[]`) requires 2FA for nobody. Role changes are
checked on subsequent browser requests and during the Studio SSO handoff.

Use the lowercase names shown above for built-in roles. Custom names are case-sensitive
and must already exist as
roles or groups; adding a name does not create permissions. Built-in names keep
the definitions above, even if a Django group has the same name. A typo in a custom
name matches nobody, so test the intended account after changing the list.

After editing the policy:

```bash
tutor config save
tutor local restart lms cms lms-worker cms-worker
```

For development, use `tutor dev restart lms cms`. Policy changes do not need an
image rebuild after this plugin version is installed in the image.

To disable enforcement for everyone:

```bash
tutor config save --set ENABLE_2FA=false
tutor local restart lms cms lms-worker cms-worker
```

Set it back to `true` to enforce the configured roles again.

**Upgrading:** rename `TWO_FACTOR_AUTH_ENABLED` (or the older `TWO_FACTOR_ENABLED`)
to `ENABLE_2FA` in `config.yml`, preserving its value, and remove the old key.
The plugin rejects obsolete enable keys to prevent a previously disabled setup
from silently becoming enabled. The former all-user policy is replaced by the
admin/staff default; set the required role list explicitly for your installation.
The proposed `ONLY_*` and `OPTIONAL_FOR_USERS` flags are not used.

The dependency version remains a separate build setting:

| Setting | Default | Description |
| --- | --- | --- |
| `TWO_FACTOR_AUTH_VERSION` | `1.18.1` | Version of `django-two-factor-auth` installed in the image. |

To upgrade the authenticator library without changing the plugin code:

```bash
tutor config save --set TWO_FACTOR_AUTH_VERSION=<version>
tutor images build openedx
```

Replace `<version>` with the exact release you want. For development, also rebuild
`openedx-dev`. Then repeat the stop, migrate and start commands above for your
environment. Test the selected version on staging before production use.

### Scope

- Browser-session TOTP only; FIDO2/passkeys, optional enrollment and invitation codes are not included.
- Studio SSO supports authorization codes issued after the LMS role check and,
  for required roles, MFA. OAuth Toolkit still
  validates client credentials, redirect URIs, PKCE and code expiry/replay. Studio
  receives the policy result and verified device through a short-lived server-side proof and records
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

## Publishing

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
publishes to TestPyPI with OIDC, and checks installation from TestPyPI. Only after
that check succeeds does it publish the same distribution artifacts to production
PyPI, without rebuilding them.

Configure both publishers before pushing a release tag. On production PyPI, use
<https://pypi.org/manage/account/publishing/> with the same project, owner,
repository and workflow values above, but set the environment to `pypi`.

Existing tags retain their original workflow. Do not move an existing release tag.

To publish the already-tested `0.1.0` release, select **Publish Python package** in
GitHub Actions, click **Run workflow**, and choose `main`. This manual path downloads
the original distributions from successful run `43866826685`, verifies their SHA-256
hashes against TestPyPI, and publishes those exact files to production PyPI. It does
not rebuild or re-upload to TestPyPI. Run it once; PyPI versions cannot be overwritten.
The original GitHub artifact must still be available (it expires under the repository's
artifact retention policy). Future releases use the normal version-tag flow.

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
