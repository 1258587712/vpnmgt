# coding:utf-8
from __future__ import unicode_literals

from django.db import models

# Create your models here.




class Vpn_Node(models.Model):
    name = models.CharField(max_length=50,verbose_name="名称")
    hostname=models.CharField(max_length=50,verbose_name="主机名")
    ip = models.GenericIPAddressField(protocol='both', unpack_ipv4=False,verbose_name="IP")
    wanip=models.GenericIPAddressField(protocol='both', unpack_ipv4=False,verbose_name="外网IP",default='0.0.0.0')
    port = models.IntegerField(verbose_name="Port")
    uid = models.CharField(max_length=32,verbose_name="用户名")
    passwd = models.CharField(max_length=50, verbose_name="密码",null=True)
    ssh_key = models.BooleanField(verbose_name="启用SSHKey", default=True)
    online = models.BooleanField(verbose_name="在线",default=False)

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = 'vpn节点'
        verbose_name_plural = 'vpn节点'

class Vpn_User(models.Model):
    name = models.CharField(max_length=50, verbose_name="用户名")
    passwd = models.CharField(max_length=50, verbose_name="密码")
    email=models.EmailField(verbose_name="邮箱")
    enable = models.BooleanField(verbose_name="在线", default=False)
    start_time=models.DateTimeField(verbose_name="开始时间")
    end_time=models.DateTimeField(verbose_name="结束时间")
    disable_lease = models.BooleanField(verbose_name="启用租期", default=True)

    nodelist = models.ManyToManyField(Vpn_Node, related_name="VPNServer", verbose_name="节点", default="")

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = 'vpn用户'
        verbose_name_plural = 'vpn用户'


class User(models.Model):
    name = models.CharField(max_length=50, verbose_name="用户名")
    passwd = models.CharField(max_length=50, verbose_name="密码")
    email = models.CharField(max_length=50, verbose_name="邮箱",null=True)
    #phone_num = models.CharField(max_length=20, verbose_name="电话",null=True)
    enable=models.BooleanField( verbose_name="启用",default=True)
    cookie_token = models.CharField(max_length=100, verbose_name="cookie",null=True)

    def __str__(self):
        return self.name

    class Meta:
        #ordering = ['-start_time',"id"]
        verbose_name = '用户管理'
        verbose_name_plural = '用户管理'

class Log(models.Model):
    type=models.CharField(max_length=50, verbose_name="类型")
    username=models.CharField(max_length=50, verbose_name="操作人")
    action=models.CharField(max_length=30, verbose_name="动作")
    time = models.DateTimeField(verbose_name="时间")
    content = models.TextField(verbose_name="内容")
    node=models.CharField(max_length=50, verbose_name="节点" ,default='')
    status=models.BooleanField( verbose_name="启用",default=False)

    class Meta:
        verbose_name = '日志'
        verbose_name_plural = '日志'