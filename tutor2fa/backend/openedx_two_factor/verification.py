"""Repeatable HTTP verification against a running LMS using a temporary account."""

import base64
import html
import re
import secrets
from contextlib import contextmanager
from urllib.parse import parse_qs, urlsplit

import requests
from django.contrib.auth import get_user_model
from django_otp.oath import totp
from django_otp.plugins.otp_static.models import StaticDevice
from django_otp.plugins.otp_totp.models import TOTPDevice

from .policy import requires_mfa


class VerificationError(Exception):
    """A login check failed; messages never include credentials or response bodies."""


def require(condition, message):
    if not condition:
        raise VerificationError(message)


def create_profile(user):
    from common.djangoapps.student.models import UserProfile

    UserProfile.objects.get_or_create(user=user)


@contextmanager
def temporary_account():
    username = "two_factor_check_" + secrets.token_hex(6)
    password = secrets.token_urlsafe(24)
    user = get_user_model().objects.create_user(
        username, username + "@example.invalid", password, is_staff=True
    )
    try:
        create_profile(user)
        yield user, password
    finally:
        user.delete()


class LoginVerification:
    def __init__(self, session, base_url, user, password):
        self.session = session
        self.base_url = base_url.rstrip("/")
        self.user = user
        self.password = password
        self.session.headers["Referer"] = self.base_url + "/"

    def get(self, path, **kwargs):
        return self.session.get(self.base_url + path, timeout=30, allow_redirects=False, **kwargs)

    def post(self, path, data):
        return self.session.post(
            self.base_url + path,
            data=data,
            timeout=30,
            allow_redirects=False,
            headers={"X-CSRFToken": self.session.cookies.get_dict().get("csrftoken", "")},
        )

    def login(self, required=True):
        require(self.get("/csrf/api/v1/token").status_code == 200, "CSRF endpoint failed.")
        response = self.post(
            "/api/user/v2/account/login_session/",
            {"email_or_username": self.user.username, "password": self.password},
        )
        require(response.status_code == 200, "Password login failed.")
        require(
            (response.json().get("redirect_url") == self.base_url + "/2fa/") == required,
            "Password login did not follow the role policy.",
        )

    def enroll(self):
        self.login()
        require(self.get("/admin/").status_code == 302, "Admin access was not gated.")
        require(
            self.get("/api/user/v1/accounts/" + self.user.username).status_code == 403,
            "API access was not gated.",
        )
        path = "/2fa/account/two_factor/setup/"
        require(self.get(path).status_code == 200, "Enrollment page failed.")
        page = self.post(path, {"two_factor_setup_view-current_step": "welcome"})
        require(page.status_code == 200, "Enrollment welcome step failed.")
        match = re.search(r'href="(otpauth://[^"]+)"', page.text)
        require(match is not None, "Enrollment did not provide an authenticator URI.")
        secret = parse_qs(urlsplit(html.unescape(match.group(1))).query).get("secret", [None])[0]
        require(secret is not None, "Enrollment did not provide an OTP secret.")
        require(
            self.get("/2fa/account/two_factor/qrcode/").status_code == 200,
            "QR code request failed.",
        )
        icon = self.session.get(
            self.base_url + "/favicon.ico", headers={"Sec-Fetch-Dest": "image"}, timeout=30
        )
        require(
            all("/2fa/" not in response.url for response in [*icon.history, icon]),
            "Favicon request redirected into enrollment.",
        )
        token = f"{totp(base64.b32decode(secret)):06d}"
        response = self.post(
            path,
            {"two_factor_setup_view-current_step": "generator", "generator-token": token},
        )
        require(response.status_code == 302, "Enrollment rejected the authenticator code.")
        require(
            TOTPDevice.objects.filter(user=self.user, confirmed=True).exists(),
            "Enrollment did not save a confirmed device.",
        )
        require(
            self.get("/2fa/").status_code == 302, "Verified login did not resume its destination."
        )
        require(self.get("/2fa/").status_code == 200, "Verified account page failed.")
        require(
            bool(self.session.cookies.get_dict().get("edx-jwt-cookie-header-payload")),
            "Verified login did not issue Open edX cookies.",
        )

    def check_recovery(self):
        require(
            self.post("/2fa/account/two_factor/backup/tokens/", {}).status_code == 302,
            "Recovery code generation failed.",
        )
        device = StaticDevice.objects.get(user=self.user, name="backup")
        token = device.token_set.first()
        require(token is not None, "No recovery codes were generated.")
        code = token.token
        self.get("/logout")
        self.login()
        require(
            self.post("/2fa/challenge/", {"otp_token": "invalid"}).status_code == 200,
            "Invalid OTP was not rejected.",
        )
        require(self.get("/admin/").status_code == 302, "Invalid OTP granted access.")
        path = "/2fa/challenge/?recovery=1"
        require(self.post(path, {"otp_token": code}).status_code == 302, "Recovery login failed.")
        require(not device.token_set.filter(token=code).exists(), "Recovery code was not consumed.")
        self.get("/logout")
        self.login()
        require(
            self.post(path, {"otp_token": code}).status_code == 200,
            "Reused recovery code was not rejected.",
        )
        require(self.get("/admin/").status_code == 302, "Reused recovery code granted access.")

    def check_role_policy(self):
        """An existing device must not override exemption; promotion gates again."""
        self.user.is_staff = False
        self.user.save(update_fields=["is_staff"])
        self.get("/logout")
        self.login(required=False)
        account_path = "/api/user/v1/accounts/" + self.user.username
        require(self.get(account_path).status_code == 200, "Exempt user's account API was gated.")
        require(
            bool(self.session.cookies.get_dict().get("edx-jwt-cookie-header-payload")),
            "Exempt login did not issue Open edX cookies.",
        )
        require(
            TOTPDevice.objects.filter(user=self.user, confirmed=True).exists(),
            "Role change removed the enrolled device.",
        )
        self.user.is_staff = True
        self.user.save(update_fields=["is_staff"])
        require(self.get(account_path).status_code == 403, "Promoted staff bypassed 2FA.")


def verify_login(base_url, report):
    """Create, verify and remove a temporary staff account; never use an existing account."""
    with temporary_account() as (user, password), requests.Session() as session:
        require(requires_mfa(user), "The live check requires staff in the required roles list.")
        session.trust_env = False
        verification = LoginVerification(session, base_url, user, password)
        verification.enroll()
        report("PASS: HTTP password login, CSRF, QR enrollment, favicon and OTP verification")
        verification.check_recovery()
        report("PASS: incorrect OTP rejected; recovery code works once and reuse is rejected")
        verification.check_role_policy()
        report("PASS: exempt enrolled user signs in normally; staff promotion requires 2FA again")
    report("PASS: temporary test account removed")
