from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("monitoreo", "0005_authlockout_escalation"),
    ]

    operations = [
        migrations.CreateModel(
            name="MonitoredEndpoint",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("nombre", models.CharField(max_length=100)),
                ("ip", models.GenericIPAddressField(unique=True)),
                ("descripcion", models.CharField(blank=True, max_length=255)),
                ("is_enabled", models.BooleanField(default=False)),
                ("last_checked_at", models.DateTimeField(blank=True, null=True)),
                ("last_is_reachable", models.BooleanField(blank=True, null=True)),
                ("last_latency_ms", models.FloatField(blank=True, null=True)),
                ("last_message", models.CharField(blank=True, max_length=255)),
            ],
            options={
                "ordering": ["nombre", "ip"],
            },
        ),
    ]
