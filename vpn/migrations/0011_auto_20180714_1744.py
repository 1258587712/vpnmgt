# -*- coding: utf-8 -*-
# Generated by Django 1.9.13 on 2018-07-14 17:44
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('vpn', '0010_auto_20180713_1758'),
    ]

    operations = [
        migrations.RenameField(
            model_name='vpn_user',
            old_name='enable_lease',
            new_name='disable_lease',
        ),
    ]
