# -*- coding: utf-8 -*-
# Generated by Django 1.10.8 on 2018-06-19 18:10
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('vpn', '0002_vpn_user_node_list'),
    ]

    operations = [
        migrations.AlterField(
            model_name='vpn_user',
            name='node_list',
            field=models.ManyToManyField(default='', related_name='VPNServer', to='vpn.Vpn_Node', verbose_name='\u8282\u70b9'),
        ),
    ]
