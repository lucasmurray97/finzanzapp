from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("finanzapp", "0005_cronlock"),
    ]

    operations = [
        migrations.AddField(
            model_name="gmailmessage",
            name="currency",
            field=models.CharField(default="CLP", max_length=3),
        ),
    ]
