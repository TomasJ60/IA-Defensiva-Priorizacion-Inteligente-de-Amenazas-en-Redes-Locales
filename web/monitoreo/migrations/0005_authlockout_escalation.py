from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("monitoreo", "0004_authlockout"),
    ]

    operations = [
        migrations.AddField(
            model_name="authlockout",
            name="admin_unlock_required",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="authlockout",
            name="escalation_level",
            field=models.PositiveIntegerField(default=0),
        ),
    ]
