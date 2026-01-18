from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("finanzapp", "0006_gmailmessage_currency"),
    ]

    operations = [
        migrations.AddField(
            model_name="transaction",
            name="time",
            field=models.TimeField(blank=True, null=True),
        ),
    ]
