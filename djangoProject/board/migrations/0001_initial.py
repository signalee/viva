# Generated by Django 3.2.25 on 2024-07-09 19:15

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Board_stats',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('updated_at', models.DateTimeField()),
                ('entity_gbn', models.CharField(max_length=2)),
                ('entity_id', models.IntegerField()),
                ('post_cnt', models.IntegerField()),
            ],
            options={
                'db_table': 'board_stats',
            },
        ),
        migrations.CreateModel(
            name='Board_virtuber',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField()),
                ('updated_at', models.DateTimeField()),
                ('virtuber_id', models.IntegerField()),
                ('members_id', models.IntegerField()),
                ('contents', models.TextField()),
            ],
            options={
                'db_table': 'board_virtuber',
            },
        ),
        migrations.CreateModel(
            name='Board_virtuber_group',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField()),
                ('updated_at', models.DateTimeField()),
                ('virtuber_group_id', models.IntegerField()),
                ('members_id', models.IntegerField()),
                ('contents', models.TextField()),
            ],
            options={
                'db_table': 'board_virtuber_group',
            },
        ),
        migrations.CreateModel(
            name='Comment_virtuber',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField()),
                ('updated_at', models.DateTimeField()),
                ('board_virtuber_id', models.IntegerField()),
                ('members_id', models.IntegerField()),
                ('contents', models.CharField(max_length=1000)),
            ],
            options={
                'db_table': 'comment_virtuber',
            },
        ),
        migrations.CreateModel(
            name='Comment_virtuber_group',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField()),
                ('updated_at', models.DateTimeField()),
                ('board_virtuber_group_id', models.IntegerField()),
                ('members_id', models.IntegerField()),
                ('contents', models.CharField(max_length=1000)),
            ],
            options={
                'db_table': 'comment_virtuber_group',
            },
        ),
        migrations.CreateModel(
            name='Reactions',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField()),
                ('updated_at', models.DateTimeField()),
                ('entity_gbn', models.IntegerField()),
                ('entity_id', models.IntegerField()),
                ('members_id', models.IntegerField()),
                ('like_dislike', models.CharField(max_length=10)),
            ],
            options={
                'db_table': 'reactions',
            },
        ),
    ]
