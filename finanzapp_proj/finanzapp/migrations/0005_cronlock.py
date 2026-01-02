from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("finanzapp", "0004_add_monthlybudget_savings_goal"),
    ]

    operations = [
        migrations.CreateModel(
            name="CronLock",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=100, unique=True)),
                ("locked_at", models.DateTimeField(blank=True, null=True)),
            ],
        ),
    ]
