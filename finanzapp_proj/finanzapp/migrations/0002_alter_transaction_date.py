# Generated by Django 4.2 on 2024-03-05 20:59

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('finanzapp', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='transaction',
            name='date',
            field=models.DateField(default='2024-03-05'),
        ),
    ]
