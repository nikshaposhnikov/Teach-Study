# Generated by Django 3.0 on 2020-02-23 22:14

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0007_auto_20200223_2338'),
    ]

    operations = [
        migrations.AddField(
            model_name='advuser',
            name='is_student',
            field=models.BooleanField(default=True, verbose_name='Студент'),
        ),
        migrations.AddField(
            model_name='advuser',
            name='is_teacher',
            field=models.BooleanField(default=False, verbose_name='Преподаватель'),
        ),
    ]
