import uuid

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


def enroll_existing_users(apps, schema_editor):
    devices = apps.get_model("otp_totp", "TOTPDevice")
    setup = apps.get_model("openedx_two_factor", "RecoverySetup")
    alias = schema_editor.connection.alias
    for user_id in (
        devices.objects.using(alias)
        .filter(confirmed=True)
        .values_list("user_id", flat=True)
        .distinct()
        .iterator()
    ):
        setup.objects.using(alias).get_or_create(user_id=user_id)


class Migration(migrations.Migration):
    initial = True
    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("otp_totp", "0001_initial"),
    ]
    operations = [
        migrations.CreateModel(
            name="RecoverySetup",
            fields=[
                (
                    "user",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        primary_key=True,
                        serialize=False,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                ("revision", models.UUIDField(default=uuid.uuid4)),
                ("saved_at", models.DateTimeField(null=True, blank=True)),
            ],
        ),
        migrations.RunPython(enroll_existing_users, migrations.RunPython.noop),
    ]
