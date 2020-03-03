# Generated by Django 3.0 on 2020-01-29 13:02

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0002_comment'),
    ]

    operations = [
        migrations.CreateModel(
            name='AdditionalComment',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('bb', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='main.Bb', verbose_name='Объявление')),
                ('comment', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='main.Comment', verbose_name='Комментарий')),
            ],
            options={
                'verbose_name': 'Комментарий',
                'verbose_name_plural': 'Комментарии',
            },
        ),
    ]