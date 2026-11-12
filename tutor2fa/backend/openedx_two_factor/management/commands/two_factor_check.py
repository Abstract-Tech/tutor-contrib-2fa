"""Run the plugin's live HTTP checks without pasting Python into Django shell."""

from urllib.parse import urlsplit

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from openedx_two_factor.verification import VerificationError, verify_login


class Command(BaseCommand):
    help = "Test the running LMS using a temporary learner, then remove that account."

    def add_arguments(self, parser):
        parser.add_argument(
            "--live",
            action="store_true",
            help="Allow temporary account creation and HTTP requests.",
        )

    def handle(self, *args, **options):
        if not options["live"]:
            raise CommandError(
                "Pass --live to create a temporary learner and test the running LMS."
            )
        if not getattr(settings, "OPENEDX_2FA_ENABLED", False):
            raise CommandError("2FA must be enabled before running this check.")
        url = getattr(settings, "OPENEDX_2FA_LMS_URL", "")
        parsed = urlsplit(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise CommandError("Configure a valid OPENEDX_2FA_LMS_URL before running this check.")
        try:
            verify_login(url, self.stdout.write)
        except VerificationError as error:
            raise CommandError(str(error)) from error
