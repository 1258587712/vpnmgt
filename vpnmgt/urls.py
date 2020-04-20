"""vpnmgt URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.9/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf.urls import url
from django.contrib import admin
from vpn import views as vpn_url

urlpatterns = [
    # vpn
    url(r'^$', vpn_url.index),
    url(r'^vpn_user$', vpn_url.vpn_user),
    url(r'^vpn_node$', vpn_url.vpn_node),
    url(r'^login$', vpn_url.login),
    url(r'^logout', vpn_url.logout),

    url(r'^[U,u]ser$', vpn_url.sys_user),
    url(r'^vpn_log$', vpn_url.log),
    url(r'^check_vpn$', vpn_url.check_vpn_user),
    url(r'^check_node$', vpn_url.check_vpn_node),    
    url(r'^get_vpn_log$', vpn_url.get_vpn_node_log),
    url(r'^admin/', admin.site.urls),
]
