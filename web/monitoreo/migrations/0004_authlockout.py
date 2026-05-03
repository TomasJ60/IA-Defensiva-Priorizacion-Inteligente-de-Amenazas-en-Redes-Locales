from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("monitoreo", "0003_securityevent"),
    ]

    operations = [
        migrations.CreateModel(
            name="AuthLockout",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("scope", models.CharField(max_length=32)),
                ("subject", models.CharField(max_length=150)),
                ("failed_attempts", models.PositiveIntegerField(default=0)),
                ("blocked_until", models.DateTimeField(blank=True, null=True)),
                ("last_attempt_at", models.DateTimeField(auto_now=True)),
            ],
            options={"unique_together": {("scope", "subject")}},
        ),
    ]
