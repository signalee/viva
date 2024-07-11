# Generated by Django 3.1 on 2023-05-25 09:35

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Members',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField()),
                ('phone', models.CharField(max_length=11)),
                ('user_id', models.CharField(max_length=30)),
                ('user_pw', models.CharField(max_length=20)),
                ('nickname', models.CharField(max_length=30)),
                ('gender', models.CharField(max_length=1)),
                ('birth_date', models.CharField(max_length=8)),
                ('user_img', models.CharField(max_length=150)),
                ('user_level', models.CharField(max_length=2)),
                ('level_figure', models.IntegerField(default=0)),
                ('duck', models.IntegerField(default=0)),
            ],
            options={
                'db_table': 'members',
            },
        ),
    ]