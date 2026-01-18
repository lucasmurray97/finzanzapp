from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("finanzapp", "0007_transaction_time"),
    ]

    operations = [
        migrations.AddField(
            model_name="transaction",
            name="email_received_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="gmailmessage",
            name="email_received_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
