from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("finanzapp", "0008_email_received_at"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="transaction",
            name="time",
        ),
        migrations.RemoveField(
            model_name="gmailmessage",
            name="purchase_time",
        ),
    ]
