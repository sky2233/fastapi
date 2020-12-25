# Generated by Django 3.1.4 on 2020-12-17 14:08

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='commFiles',
            fields=[
                ('id', models.CharField(max_length=255, primary_key=True, serialize=False)),
                ('file_id', models.CharField(max_length=255)),
                ('type', models.CharField(max_length=50)),
                ('score', models.CharField(max_length=10)),
                ('reputation', models.CharField(max_length=10)),
                ('date', models.CharField(max_length=15)),
                ('tags', models.CharField(max_length=255)),
            ],
        ),
        migrations.CreateModel(
            name='ipDomain',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('type', models.CharField(max_length=50)),
                ('score', models.CharField(max_length=10)),
                ('reputation', models.CharField(max_length=10)),
            ],
        ),
        migrations.CreateModel(
            name='refFiles',
            fields=[
                ('id', models.CharField(max_length=255, primary_key=True, serialize=False)),
                ('file_id', models.CharField(max_length=255)),
                ('type', models.CharField(max_length=50)),
                ('score', models.CharField(max_length=10)),
                ('reputation', models.CharField(max_length=10)),
                ('date', models.CharField(max_length=15)),
                ('tags', models.CharField(max_length=255)),
            ],
        ),
    ]
