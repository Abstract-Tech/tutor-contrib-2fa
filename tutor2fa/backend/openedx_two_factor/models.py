import uuid

from django.conf import settings
from django.db import models


class RecoverySetup(models.Model):
    """Track whether the user acknowledged saving the current recovery-code set."""

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, primary_key=True
    )
    revision = models.UUIDField(default=uuid.uuid4)
    saved_at = models.DateTimeField(null=True, blank=True)
