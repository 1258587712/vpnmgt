# -*- coding: utf-8 -*-
# Generated by Django 1.9.13 on 2018-07-10 14:18
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('vpn', '0005_auto_20180619_1820'),
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=50, verbose_name='\u7528\u6237\u540d')),
                ('passwd', models.CharField(max_length=50, verbose_name='\u5bc6\u7801')),
                ('enable', models.BooleanField(default=True, verbose_name='\u542f\u7528')),
                ('cookie_token', models.CharField(max_length=100, null=True, verbose_name='cookie')),
            ],
            options={
                'verbose_name': '\u7528\u6237\u7ba1\u7406',
                'verbose_name_plural': '\u7528\u6237\u7ba1\u7406',
            },
        ),
    ]
