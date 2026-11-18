from .models import RecoverySetup


def recovery_pending(user):
    return RecoverySetup.objects.filter(user=user, saved_at__isnull=True).exists()
