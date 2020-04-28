# coding:utf-8
from django.shortcuts import render

from django.http import  HttpResponseRedirect,HttpRequest,HttpResponse
from .models import *
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
import datetime,json,base64,os,string,sys,threading,time
import json,time,os,commands,sys
from random import choice
from crontab import CronTab

from django.conf import settings

reload(sys)
sys.setdefaultencoding('utf8')


def reload_crontab(ver=os.popen("rpm -q centos-release |awk -F '-' '{print $3}'").read()):
    if ver  >= 7 : 
        status, result = commands.getstatusoutput('systemctl status crond')            
        cmd="systemctl reload crond"
        start_cmd="systemctl restart crond"
    elif ver <= 6:
        status, result = commands.getstatusoutput('service crond status')
        cmd="service crond reload"
        start_cmd="service crond  restart"
  
    if status == 0:
        status, result = commands.getstatusoutput(cmd)
    else:
        status, result = commands.getstatusoutput(start_cmd)        
        status, result = commands.getstatusoutput(cmd)
    #result = os.popen(cmd).read()
  
def cron_add(interval,cmd,comment, isenable):
    db_name=os.path.basename(settings.BASE_DIR) 
    comment=db_name+'_'+str(comment)
    base_dir=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    my_user_cron = CronTab(user=True)
    job = my_user_cron.new(command=cmd)
    job.setall(interval)
    job.set_comment(str(comment))
    job.enable(isenable)
    my_user_cron.write()
    
    reload_crontab()

def cron_delete(comment):
    db_name=os.path.basename(settings.BASE_DIR) 
    comment=db_name+'_'+str(comment)
    my_user_cron = CronTab(user=True)
    my_user_cron.remove_all(comment=str(comment))
    my_user_cron.write()
    reload_crontab()

def cron_exec(comment):
    db_name=os.path.basename(settings.BASE_DIR) 
    comment=db_name+'_'+str(comment)

    my_user_cron = CronTab(user=True)
    iter = my_user_cron.find_comment(str(comment))
    for job  in iter:
        if job.comment == str(comment):
            job.run()
    #reload_crontab()
    #my_user_cron.write()

def cron_disable(comment):
    db_name=os.path.basename(settings.BASE_DIR) 
    comment=db_name+'_'+str(comment)
    my_user_cron = CronTab(user=True)
    iter = my_user_cron.find_comment(str(comment))
    for job in iter:
        if job.comment == str(comment):
            job.enable(False)
    my_user_cron.write()
    reload_crontab()

def check_cron_exist(comment):
    db_name=os.path.basename(settings.BASE_DIR) 
    comment=db_name+'_'+str(comment)
    
    my_user_cron = CronTab(user=True)
    iter = my_user_cron.find_comment(comment)
    stats=False
    for job in iter:
        if job.comment == comment:
            stats=True
    return stats

def cron_enable(comment):
    db_name=os.path.basename(settings.BASE_DIR) 
    comment=db_name+'_'+str(comment)
    
    my_user_cron = CronTab(user=True)
    iter = my_user_cron.find_comment(str(comment))
    for job in iter:
        if job.comment == str(comment):
            job.enable()
    my_user_cron.write()
    reload_crontab()
    
def ssh_run(host, port, userid, passwd, cmd,runway, issshkey):
    import paramiko,sys
    reload(sys)
    sys.setdefaultencoding('utf8')
    if issshkey is True:
        private_key = paramiko.DSSKey.from_private_key_file('/root/.ssh/id_dsa')
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        if issshkey is True:
            ssh.connect(hostname=host, port=int(port), username=userid, pkey=private_key)
        else:
            ssh.connect(hostname=host, port=int(port), username=userid, password=passwd)
    except:
        return False, ""
    else:
        # 执行命令
        if runway == 'shell':
            stdin, stdout, stderr = ssh.exec_command(cmd)
            result = stdout.read().decode().encode("utf-8")
        elif runway == 'http':
            stdin, stdout, stderr = ssh.exec_command('curl -k "' + cmd + '"')
            result = stdout.read()
        status = True
        if len(result) == 0:
            result = stderr.read().decode().encode("utf-8")
            status = False
            if len(result) == 0:
                status = True
    ssh.close()

    return status, result

def sendmail(TO,SUBJECT,msgtext):
    import smtplib, sys
    from email.mime.text import MIMEText

    HOST = "smtp.meilele.com"

    #SUBJECT = 'Python SMTP 邮件测试'
    #TO = 'lilin5@meilele.com,1258587712@qq.com'

    FROM = "nagios@meilele.com"
    msg = MIMEText(msgtext, "plain", "utf-8")
    msg['Subject'] = SUBJECT
    msg['From'] = FROM
    msg['To'] = TO
    try:
        server = smtplib.SMTP()
        server.connect(HOST, "25")
        # server.starttls()#启动安全传输
        server.login("nagios@meilele.com", "B)q].sGPfT6i_1Ux")
        server.sendmail(FROM, [TO,"ZYywz@meilele.com"], msg.as_string())
        server.quit()

    except Exception, e:
        return False,str(e)
    else:
        #print "Email sent successfully!"
        return True,'Email sent successfully!'

def install_pptp(request, ip, port, user, passwd, iskey, isenable):
    if isenable is False:
        cmd = """service pptpd stop
chkconfig pptpd off
#yum remove -y pptpd"""
    else:
        cmd ="""cat >~/pptp_install.sh<<EOF
#!/bin/bash

##################################
#iptables -A POSTROUTING -s 172.16.36.0/24 -o eth0 -j MASQUERADE

iptables -F
iptables -t nat -F
iptables -t mangle -F
iptables -X
iptables -t nat -X
iptables -t mangle -X

sysctl -w net.ipv4.ip_forward=1


iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

#iptables -D FORWARD -d 172.16.36.0/24 -j ACCEPT
#iptables -D INPUT -p tcp --dport 1723 -m state --state NEW -j ACCEPT
#iptables -t nat -D POSTROUTING -s 172.16.36.0/24 -j SNAT --to-source """+ip+"""


iptables -A FORWARD -d 172.16.36.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 1723 -m state --state NEW -j ACCEPT
iptables -t nat -A POSTROUTING -s 172.16.36.0/24 -j SNAT --to-source """+ip+"""

service iptables save
service iptables restart
##################################

version=\`rpm -q centos-release |awk -F '-' '{print \$3}'\`

if [ \`rpm -aq pptpd |wc -l\` -eq 0 ] ;then
    yum install -y ppp wget net-tools
    if [[ "\`uname -r\`" =~ "x86_64" ]] ;then
        wget http://poptop.sourceforge.net/yum/stable/packages/pptpd-1.4.0-1.el6.x86_64.rpm      
        rpm -ivh pptpd-1.4.0-1.el6.x86_64.rpm
    else
        wget http://poptop.sourceforge.net/yum/stable/packages/pptpd-1.4.0-1.el6.i686.rpm 
        rpm -ivh pptpd-1.4.0-1.el6.i686.rpm
    fi
fi

sed -i '/localip/d' /etc/pptpd.conf
echo -e 'localip 172.16.36.1' >>/etc/pptpd.conf 

sed -i '/remoteip/d' /etc/pptpd.conf
echo -e "remoteip 172.16.36.10-217" >>/etc/pptpd.conf 

sed -i '/ms-dns/d' /etc/ppp/options.pptpd
echo -e "ms-dns 172.16.36.1" >>/etc/ppp/options.pptpd


if [ \`grep -c 'login" >>' /etc/ppp/ip-up\` -eq 0 ]  ;then
    sed -i '/exit/ i echo "\`date "+%F %T"\`,\$6,\$PEERNAME,\$5,login" >>/var/log/pptpd.log' /etc/ppp/ip-up
fi

if [ \`grep -c 'logout" >>' /etc/ppp/ip-down\` -eq 0 ]  ;then
    sed -i '/exit/ i echo "\`date "+%F %T"\`,\$6,\$PEERNAME,\$5,logout" >>/var/log/pptpd.log' /etc/ppp/ip-down
fi



if [ \`grep -c 'nameserver' /etc/resolv.conf\` -ne 0 ] ;then
    sed -i "s#ms-dns.*#ms-dns \$(grep nameserver /etc/resolv.conf |head -n 1 |awk '{print \$2}')#g" /etc/ppp/options.pptpd
fi

sysctl -w net.ipv4.ip_forward=1

#sed -i 's/net.ipv4.ip_forward = 0/net.ipv4.ip_forward = 1/g'  /etc/sysctl.conf  
#sysctl -p

case \$version in
    7)        
        if [ \`grep -c 'ip link set \$1 mtu 1500' /etc/ppp/ip-up\` -eq 0 ]  ;then
            sed -i '/exit 0/i\ip link set \$1 mtu 1500' /etc/ppp/ip-up
        fi
        systemctl restart pptpd
        systemctl enable pptpd
    ;;
    6)
        if [ \`grep -c 'ifconfig \$1 mtu 1500' /etc/ppp/ip-up\` -eq 0 ]  ;then
            sed -i '/exit 0/i\ifconfig \$1 mtu 1500' /etc/ppp/ip-up
        fi
        service pptpd restart
        chkconfig pptpd on
    ;;
esac



EOF

bash ~/pptp_install.sh

"""

    if iskey is False:
        status, result = ssh_run(ip, port, user, passwd, cmd, 'shell', True)
    else:
        status, result = ssh_run(ip, port, user, passwd, cmd, 'shell', False)

    write_log('系统日志', request.session.get('username'), '配置pptp服务', datetime.datetime.now(), ip + '\n' + cmd + '\n' + result, status)
    return status

#sshkey
def sshkey_copy(request,ip, port, user, passwd,isenable):
    home_path=os.popen("echo $HOME").read().split("\n")[0]
    os.popen("mkdir -p $HOME/.ssh;ssh-keygen -t dsa -P '' -f $HOME/.ssh/id_dsa")
    
    pub_path=home_path+'/.ssh/id_dsa.pub'
    dsa_path=home_path+'/.ssh/id_dsa'
    if os.path.exists(pub_path) and os.path.exists(dsa_path):
        pass
    else:
        os.popen("ssh-keygen -t dsa -P '' -f " + dsa_path).read()
    if isenable is False:
        keycmd = "sed -i '/"+os.popen("cat " + pub_path).read().split('\n')[0].split()[2]+"/'d  ~/.ssh/authorized_keys"# ;exit"
        status,result=ssh_run(ip, port, user, '', keycmd,'shell',True)
        #write_log('系统日志', request.session.get('username'), '删除sshkey', datetime.datetime.now(), keycmd+'\n'+result, status)
    else:
        cmd="grep -c '" + os.popen("cat " + pub_path).read().split('\n')[ 0] + "' ~/.ssh/authorized_keys"
        status, result = ssh_run(ip, port, user, passwd, cmd,'shell',False)
        #write_log('系统日志', request.session.get('username'), '配置sshkey', datetime.datetime.now(), cmd+'\n'+result, status)

        if status is True and result == 0:
            cmd="echo '" + os.popen("cat " + pub_path).read().split('\n')[ 0] + "' >>~/.ssh/authorized_keys"
            status, result = ssh_run(ip, port, user, passwd, cmd+'\n'+result,'shell', False)
        else:
            cmd='mkdir -p ~/.ssh ;chmod 700 ~/.ssh ;touch ~/.ssh/authorized_keys ;chmod 600 ~/.ssh/authorized_keys'
            status, result=ssh_run(ip, port, user, passwd, cmd,'shell',False)
            #write_log('系统日志', request.session.get('username'), '配置sshkey', datetime.datetime.now(), cmd+'\n'+result, status)

            cmd= "echo '" + os.popen("cat " + pub_path).read().split('\n')[0] + "' >>~/.ssh/authorized_keys"
            status, result = ssh_run(ip, port, user, passwd,cmd+'\n'+result, 'shell',False)
        #write_log('系统日志', request.session.get('username'), '配置sshkey', datetime.datetime.now(), cmd+'\n'+result, status)

    return status#, result

def get_url(request):
    try:
        referer = request.META['HTTP_REFERER'].split('?')[1]
    except:
        referer = ''
    url_get={}
    try:
        for u in referer.split('&'):

            url_get[u.split('=')[0]] = u.split('=')[1]
    except:
        try:
            url_get[u.split('=')[0]] = u.split('=')[1]
        except:
            url_get['url']='/'
    return url_get
# 登陆
def login(request):
    url_get=get_url(request)
    if userauth(request):
        return HttpResponseRedirect(url_get['url'])
    else:
        if request.POST:
            username, password = request.POST['username'], request.POST['passwd']
            passwd = base64.encodestring(password)
            try:
                user = User.objects.get(name=username, passwd=passwd)
                if user:
                    request.session['username'] = user.name  # 在Django 中一句话搞定
                    request.session['csrfmiddlewaretoken'] = request.POST['csrfmiddlewaretoken']
                    User.objects.filter(name=username, passwd=passwd).update(cookie_token=request.POST['csrfmiddlewaretoken'])
                    # print(request.COOKIES.get('sessionid'))
                    # return redirect('/index')
                    # response = HttpResponseRedirect('/')
                    # response.set_cookie('username', username, 3600)
                    return HttpResponseRedirect(url_get['url'])
            except:
                #context = {}
                #context['username'] = username
                #context['passwd'] = password
                #context['stats'] = "用户名和密码不匹配！"
                #return render(request, 'login.html', context)
                try:
                    return HttpResponseRedirect("login?url="+url_get['url']+"&user="+username)
                except:
                    return HttpResponseRedirect("login?user=" + username)

        else:
            try:
                username = request.GET.get('user')
                context = {}
                if username is None:
                    pass
                else:
                    context['username'] = username
                    context['stats'] = "用户名和密码不匹配！"
                return render(request, 'login.html', context)
            except:
                #path_info = request.META['PATH_INFO']
                return render(request, 'login.html', {})

def userauth(request):
    #usernamestr = request.COOKIES.get('username')
    #usertoken = request.COOKIES.get('csrftoken')
    #sessionid=request.COOKIES.get('sessionid')
    usernamestr=request.session.get('username')
    cookie_token = request.session.get('csrfmiddlewaretoken')
    #user = Cron_User.objects.filter(name=usernamestr, cookie_token=usertoken)
    if User.objects.count() == 0 :
        User.objects.create(name='admin', passwd=base64.encodestring('admin'),email='admin@admin.com')
    user = User.objects.filter(name=usernamestr, cookie_token=cookie_token)
    if user:
        return True
    else:
        return False

def more_page(request,values):
    contact_list = values
    paginator = Paginator(contact_list, 12)
    if request.POST.has_key('page'):
        page = request.POST['page']
    else:
        if request.POST.has_key('pagenum'):
            page=request.POST['pagenum']
        else:
            page = 1 
    
    #page = request.GET.get('page')
    if 'search' in request.POST:
        page = 1
    num_list = range(0, 5)
    try:
        context = paginator.page(page)
    except PageNotAnInteger:
        # If page is not an integer, deliver first page.
        context = paginator.page(1)
    except EmptyPage:
        # If page is out of range (e.g. 9999), deliver last page of results.
        context = paginator.page(paginator.num_pages)
    return num_list,context

def write_log(type,user,action,time,content,status):
    #while True:
    Log.objects.create(type=type, username=user, action=action, time=time, content=content, status=status)

def logout(request):
    #url_get = get_url(request)
    #response=HttpResponseRedirect('/login')
    if userauth(request):
        #username = request.COOKIES.get('username')
        #response.delete_cookie('username')
        #response.delete_cookie('csrftoken')
        #Cron_User.objects.filter(name=username).update(cookie_token='')
        del request.session['username']
        request.session.delete("session_key")
    return HttpResponseRedirect('/login')

#index
def index(request):
    context = {}
    context['title'] = 'Index'
    if userauth(request):
        #context['login_user'] = request.session.get('username')
        #return render(request, 'base.html', context)

        return HttpResponseRedirect("/vpn_user")
    else:
        #return HttpResponseRedirect('/login')
        path_info = request.META['PATH_INFO']
        return HttpResponseRedirect("/login?url=" + path_info)




def get_sys_user_search_values(request):
    context={}
    if request.POST.has_key('search_text'):
        search_text = request.POST['search_text']
    else:
        search_text = ''
    if request.POST.has_key('user_enable'):
        user_enable = request.POST['user_enable']
        context['user_enable'] = user_enable
    else:
        user_enable = ''


    if len(search_text) == 0 and len(user_enable) == 0:
        context['values'] = User.objects.values()
    else:
        if len(search_text) == 0:
            if user_enable == 'True':
                user_enable = True
            else:
                user_enable = False
            context['values'] = User.objects.filter(enable=user_enable).values()
        else:
            if len(user_enable) == 0:
                context['values'] = User.objects.filter(name__contains=search_text).values()
            else:
                if user_enable == 'True':
                    user_enable = True
                else:
                    user_enable = False
                context['values'] = User.objects.filter(name__contains=search_text, enable=user_enable).values()

        context['search_text'] = search_text
    context['num_list'], context['values'] = more_page(request, context['values'])
    return context


def sys_user(request):
    if userauth(request) is False:
        path_info = request.META['PATH_INFO']
        return HttpResponseRedirect("/login?url=" + path_info)
    else:
        context = {}
        context['title'] = 'User'
        context['items'] =  ["用户名",  "是否启用",""]
        context['keys'] = ["name","enable", "id"]
        context['values'] = User.objects.values()
        context['num_list'], context['values'] = more_page(request, context['values'])
        context['login_user'] = request.session.get('username')
        if request.POST:
            if 'edit' in request.POST:
                hostlist = User.objects.filter(id=request.POST['edit']).values()
                if hostlist:
                    context['input_name'] = hostlist[0]['name']
                    context['input_email'] = hostlist[0]['email']
                    passwd = base64.decodestring(hostlist[0]['passwd'])
                    context['input_passwd'] = passwd
                    if hostlist[0]['enable'] is True:
                        context['input_enable'] = "checked"


                else:
                    context['add_node_stats'] = "获取数据失败！"
                context['hid'] = request.POST['edit']
                context['edit'] = request.POST['edit']
                context = dict(context.items() + get_sys_user_search_values(request).items())
                return render(request, 'user.html', context)
            elif 'save' in request.POST:
                context['input_name'] = request.POST['input_name']
                context['input_email'] = request.POST['input_email']
                context['input_passwd'] = request.POST['input_passwd']
                passwd=base64.encodestring(request.POST['input_passwd'])
                try:
                    input_enable = request.POST['input_enable']
                except:
                    input_enable = False
                else:
                    context['input_enable'] = "checked"
                    input_enable=True
                if len(request.POST['save'].strip()):
                    context['edit'] = request.POST['save']
                    context['hid'] = request.POST['save']
                    #更新数据
                    try:
                        User.objects.filter(id=request.POST['save']).update(name=request.POST['input_name'], \
                                                                            passwd=passwd,email=request.POST['input_email'],enable=input_enable)
                    except:
                        context['add_node_stats'] = "更新失败！"
                    else:
                        context['add_node_stats'] = "更新成功！"
                else:
                    #新增数据
                    context['edit'] = request.POST['input_name']
                    if User.objects.filter(name=request.POST['input_name']).count():
                        context['add_node_stats'] = "用户已经存在！"
                    else:

                        try:
                            obj = User.objects.create(name=request.POST['input_name'], passwd=passwd, email=request.POST['input_email'], enable=input_enable)
                            context['hid'] = obj.id
                        except:
                            context['add_node_stats'] = "用户添加失败！"
                        else:
                            context['add_node_stats'] = "添加成功！"
                context = dict(context.items() + get_sys_user_search_values(request).items())
                return render(request, 'user.html', context)
            elif 'enable' in request.POST:

                try:
                    User.objects.filter(id=request.POST['enable']).update(enable=True)
                except:
                    pass
                finally:
                    context = dict(context.items() + get_sys_user_search_values(request).items())
                return render(request, 'user.html', context)
            elif 'disable' in request.POST:

                try:
                    User.objects.filter(id=request.POST['disable']).update(enable=False)
                except:
                    pass
                finally:
                    context = dict(context.items() + get_sys_user_search_values(request).items())
                return render(request, 'user.html', context)
            elif 'del' in request.POST:
                request.POST['del']
                try:
                    User.objects.filter(id=request.POST['del']).delete()
                except:
                    pass
                finally:
                    context = dict(context.items() + get_sys_user_search_values(request).items())
                return render(request, 'user.html', context)

            elif 'search' in request.POST or 'page' in request.POST:
                context = dict(context.items() + get_sys_user_search_values(request).items())
                return render(request, 'user.html', context)
        else:
            context = dict(context.items() + get_sys_user_search_values(request).items())
            return render(request, 'user.html', context)



def vpn_user_add_or_remove(request,uobj,node_id,isadd):
    node=Vpn_Node.objects.get(id=node_id)
    if isadd:
        cmd="echo " +uobj.name+" pptpd "+uobj.passwd+" \* >>/etc/ppp/chap-secrets ;service pptpd reload"

        if uobj.disable_lease :
            timestr='租用时间：永久'
        else:
            timestr='租用时间：'+str(uobj.start_time)+' 至 '+str(uobj.end_time)

        msgtext = '''VPN账号信息已激活：
                            vpn服务器地址：''' + node.wanip + '''
                            vpn账号：''' + uobj.name + '''
                            vpn密码：''' + uobj.passwd + '''
                            VPN新建工具:http://indoor.meilele.com/download/%E8%84%9A%E6%9C%AC%E5%B7%A5%E5%85%B7/MEILELE_VPN.exe
                            '''+timestr


    else:
        cmd = "sed -i '/"+uobj.name + " pptpd " + uobj.passwd+"/d' /etc/ppp/chap-secrets ;service pptpd reload"

        if uobj.disable_lease :
            timestr='租用时间：永久'
        else:
            timestr='租用时间：'+str(uobj.start_time)+' 至 '+str(uobj.end_time)

        msgtext = '''VPN账号信息已过期：
                            vpn服务器地址：''' + node.wanip + '''
                            vpn账号：''' + uobj.name + '''
                            vpn密码：''' + uobj.passwd + '''
                            VPN新建工具:http://indoor.meilele.com/download/%E8%84%9A%E6%9C%AC%E5%B7%A5%E5%85%B7/MEILELE_VPN.exe
                            '''+timestr



    status, result = ssh_run(node.ip, node.port, node.uid, node.passwd, cmd, 'shell', node.ssh_key)

    sendmail_status,errmsg = sendmail(uobj.email, 'VPN账号通知', msgtext)

    write_log('系统日志', request.session.get('username'),'修改pptp配置文件' , datetime.datetime.now(), node.ip+'\n'+ cmd+'\nsendmail:'+str(sendmail_status)+'\nmailmsg:'+msgtext, status)
    return status,result


def get_random_passwd(length=8,chars=string.ascii_letters + string.digits):
    passwd=''.join([choice(chars) for i in range(length)])
    return str(passwd)


def save_vpn_user(request,context):
    #context['input_email'] = '&#10;'.join(request.POST['input_email'].split())
    context['input_email'] = request.POST['input_email']
    print(type(request.POST['input_email']))
    context['user_node'] = json.dumps(request.POST.getlist('user_node'))
    if request.POST.has_key('input_enable'):
        context['input_enable'] = "checked"
        input_enable = True
    else:
        input_enable = False

    if request.POST.has_key('input_enable_lease'):
        context['start_time'] = ''
        context['end_time'] = ''
        context['input_enable_lease'] = "checked"
        input_enable_lease = True
    else:
        input_enable_lease = False
        context['start_time'] = request.POST['start_time']
        context['end_time'] = request.POST['end_time']

        
    if len(request.POST['save'].strip()):
        context['hid'] = request.POST['save']
        context['edit'] = request.POST['save']
        username = request.POST['input_email'].split('@')[0]
        # 更新数据
        # tmp = [val for val in node_list_id if val not in request.POST.getlist('user_node')]
        # print(tmp)
        try:
            obj = Vpn_User.objects.get(id=request.POST['save'])
            oldenable=obj.enable
            if input_enable_lease is True:

                Vpn_User.objects.filter(id=request.POST['save']).update(name=username, enable=input_enable,
                                                                        email=request.POST['input_email'],
                                                                        disable_lease=input_enable_lease)
            else:
                Vpn_User.objects.filter(id=request.POST['save']).update(name=username,
                                                                        enable=input_enable,
                                                                        email=request.POST['input_email'],
                                                                        start_time=context['start_time'],
                                                                        end_time=context['end_time'],
                                                                        disable_lease=input_enable_lease)



            old_list=[]
            new_list=[]
            for nid in request.POST.getlist('user_node'):
                new_list.append(int(nid))

            for old_node in Vpn_User.objects.filter(id=request.POST['save']).values('nodelist'):
                if old_node is not None:
                    old_list.append(old_node['nodelist'])
            #print(new_list)
            #print(old_list)
            if oldenable:
                for oid in old_list:
                    if oid not in new_list:
                        #print("del old %s" % oid )
                        vpn_user_add_or_remove(request, obj, oid, False)


            obj.nodelist.clear()
            for nid in new_list:
                obj.nodelist.add(nid)
                if input_enable:
                    if nid not in old_list:
                        #print(old_list)
                        #print("add new  %s" % nid )
                        vpn_user_add_or_remove(request, obj, nid, True)
                    elif oldenable is False:
                        #print("add new oldFa %s" % nid)
                        vpn_user_add_or_remove(request, obj, nid, True)
                elif  oldenable:
                    #print("del new %s" % nid )
                    vpn_user_add_or_remove(request, obj, nid, False)



        except:
            context['add_node_stats'] = "更新失败！"
            # context['edit']=request.POST['save']
        else:
            context['add_node_stats'] = "更新成功！"
            write_log('系统日志', request.session.get('username'), '更新账号', datetime.datetime.now(),
                      Vpn_User.objects.filter(id=request.POST['save']).values(), True)

    else:
        # 新增数据
        user_email_list=request.POST['input_email'].split()
        ex_msg=''
        err_msg=''

        if len(user_email_list) > 1:
            context['more'] = 'more'
        else:
            context['more'] = ''

        for user_email in user_email_list:
            username = user_email.split('@')[0]
            context['edit'] = username
            if Vpn_User.objects.filter(name=username).count():

                if len(user_email_list) > 1:
                    ex_msg= ex_msg+ user_email + ","
                else:
                    context['add_node_stats'] = '用户已经存在！'
            else:


                passwd = get_random_passwd()
                if input_enable_lease is True:

                    obj = Vpn_User.objects.create(name=username,
                                                  passwd=passwd,
                                                  email=user_email,
                                                  enable=input_enable, start_time=datetime.datetime.now(),
                                                  end_time=datetime.datetime.now(),
                                                  disable_lease=input_enable_lease)
                else:

                    obj = Vpn_User.objects.create(name=username,
                                                  passwd=passwd,
                                                  email=user_email,
                                                  enable=input_enable, start_time=request.POST['start_time'],
                                                  end_time=request.POST['end_time'],
                                                  disable_lease=input_enable_lease)

                if len(request.POST.getlist('user_node')) > 0:
                    for mem in request.POST.getlist('user_node'):
                        obj.nodelist.add(mem)
                        if input_enable:
                            vpn_user_add_or_remove(request, obj, mem, True)
                try:
                    context['hid'] = obj.id
                except:

                    if len(user_email_list) > 1:
                        err_msg = err_msg + user_email + ","
                    else:
                        context['add_node_stats'] = '用户添加失败！'
                else:
                    write_log('系统日志', request.session.get('username'), '新建账号', datetime.datetime.now(),Vpn_User.objects.filter(id=context['hid']).values(), True)
                    context['add_node_stats'] = "添加成功！"
        if len(ex_msg) > 0 or len(err_msg) > 0:
            if len(ex_msg) > 0:
                ex_msg=ex_msg+str('已经存在！')
            if len(err_msg) > 0:
                err_msg=err_msg+str('添加失败！')

            context['add_node_stats'] = ex_msg + err_msg

        if len(user_email_list) > 1:
            context['edit'] = 'more'
            context['hid'] = ''
        print(context['add_node_stats'] )
    return context


def vpn_user(request):
    if userauth(request) is False:
        path_info = request.META['PATH_INFO']
        return HttpResponseRedirect("/login?url=" + path_info)
    else:
        context = {}
        context['title'] = 'vpn_user'
        context['items'] =  ["邮箱","用户名", "密码","账号永不过期","租用时间", "是否启用",""]
        context['node_list'] = Vpn_Node.objects.values()
        #context['values'] = Vpn_User.objects.values()
        #print( Vpn_User.objects.filter(id=1).values("nodelist"))
        #context['num_list'], context['values'] = more_page(request, context['values'])
        context['login_user'] = request.session.get('username')
        if request.POST:
            if 'edit' in request.POST:
                obj=Vpn_User.objects.get(id=request.POST['edit'])
                context['input_email'] = obj.email

                node_list_id=[]
                for node in Vpn_User.objects.filter(id=request.POST['edit']).values('nodelist'):
                    node_list_id.append(node['nodelist'])
                context['user_node'] =node_list_id

                if obj.disable_lease:
                    context['input_enable_lease'] = "checked"
                else:
                    context['start_time'] = obj.start_time
                    context['end_time'] = obj.end_time

                if obj.enable:
                    context['input_enable'] = "checked"
                context['hid'] = request.POST['edit']
                context['edit'] = request.POST['edit']

                context = dict(context.items() + get_vpn_user_search_values(request).items())
                return render(request, 'vpn_user.html', context)
            elif  'save' in request.POST:
                context['input_email'] = request.POST['input_email']
                context['user_node'] = json.dumps(request.POST.getlist('user_node'))
                if request.POST.has_key('input_enable'):
                    context['input_enable'] = "checked"

                if request.POST.has_key('input_enable_lease'):
                    input_enable_lease = True
                else:
                    input_enable_lease = False
                    context['start_time'] = request.POST['start_time']
                    context['end_time'] = request.POST['end_time']

                if input_enable_lease is False:
                    if len(request.POST['start_time']) == 0 or len(request.POST['end_time']) == 0  :
                        context['edit'] = request.POST['input_email']
                        context['add_node_stats'] = "租用时间不能为空！"
                    else:
                        context = dict(context.items() + save_vpn_user(request,context).items())
                else:
                    context = dict(context.items() + save_vpn_user(request, context).items())


                context = dict(context.items() + get_vpn_user_search_values(request).items())
                return render(request, 'vpn_user.html', context)
            elif 'enable' in request.POST:
                userobj = Vpn_User.objects.get(id=request.POST['enable'])
                if userobj.enable is False:
                    for node in Vpn_User.objects.filter(id=request.POST['enable']).values('nodelist'):
                        if node['nodelist'] is not None:
                            vpn_user_add_or_remove(request, userobj, node['nodelist'], True)

                write_log('系统日志', request.session.get('username'), '启用账号', datetime.datetime.now(), Vpn_User.objects.filter(id=request.POST['enable']).values(), True)
                Vpn_User.objects.filter(id=request.POST['enable']).update(enable=True)
                try:
                    pass

                except :
                    pass
                finally:
                    context = dict(context.items() + get_vpn_user_search_values(request).items())
                return render(request, 'vpn_user.html', context)
            elif 'disable' in request.POST:

                try:
                    userobj = Vpn_User.objects.get(id=request.POST['disable'])
                    if userobj.enable:
                        for node in Vpn_User.objects.filter(id=request.POST['disable']).values('nodelist'):
                            if node['nodelist'] is not None:
                                vpn_user_add_or_remove(request, userobj, node['nodelist'], False)

                    write_log('系统日志', request.session.get('username'), '禁用账号', datetime.datetime.now(), Vpn_User.objects.filter(id=request.POST['disable']).values(), True)
                    Vpn_User.objects.filter(id=request.POST['disable']).update(enable=False)


                except:
                    pass
                finally:
                    context = dict(context.items() + get_vpn_user_search_values(request).items())
                return render(request, 'vpn_user.html', context)
            elif 'del' in request.POST:
                try:
                    userobj=Vpn_User.objects.get(id=request.POST['del'])
                    if userobj.enable:
                        for node in Vpn_User.objects.filter(id=request.POST['del']).values('nodelist'):
                            if node['nodelist'] is not None:
                                vpn_user_add_or_remove(request,userobj , node['nodelist'], False)

                    write_log('系统日志', request.session.get('username'), '删除账号', datetime.datetime.now(),
                              Vpn_User.objects.filter(id=request.POST['del']).values(), True)
                    Vpn_User.objects.filter(id=request.POST['del']).delete()

                except:
                    pass
                finally:
                    context = dict(context.items() + get_vpn_user_search_values(request).items())
                return render(request, 'vpn_user.html', context)
            elif 'search' in request.POST or 'page' in request.POST:
                context = dict(context.items() + get_vpn_user_search_values(request).items())
                return render(request, 'vpn_user.html', context)
        else:
            context = dict(context.items() + get_vpn_user_search_values(request).items())
            context['input_enable'] = "checked"
            return render(request, 'vpn_user.html', context)


def get_vpn_user_search_values(request):
    context={}
    if request.POST.has_key('search_text'):
        search_text = request.POST['search_text']
    else:
        search_text=''
    if request.POST.has_key('user_enable'):
        context['user_enable'] = request.POST['user_enable']

    try:
        if request.POST['user_enable'] == "True":
            user_enable = True
        elif request.POST['user_enable'] == "False":
            user_enable = False
        else:
            user_enable = None
    except:
        user_enable=None


    try:
        select_node = request.POST['select_node']
    except:
        select_node=''


    #print(Vpn_User.objects.filter(nodelist=select_node).values())
    #print(select_node)
    if len(search_text) == 0 and len(select_node)==0 and user_enable is None:
        context['values'] = Vpn_User.objects.values()
    else:
        if len(search_text) == 0:
            if len(select_node)==0:
                if user_enable is None:
                    context['values'] = Vpn_User.objects.filter().values()
                else:
                    context['values'] = Vpn_User.objects.filter(enable=user_enable).values()
            else:

                if user_enable is None:
                    context['values'] = Vpn_User.objects.filter( nodelist=select_node).values()
                else:
                    context['values'] = Vpn_User.objects.filter(enable=user_enable, nodelist=select_node).values()
        else:
            if len(select_node) == 0:

                if user_enable is None:
                    context['values'] = Vpn_User.objects.filter(name__contains=search_text).values()
                else:
                    context['values'] = Vpn_User.objects.filter(name__contains=search_text, enable=user_enable).values()
            else:

                if user_enable is None:
                    context['values'] = Vpn_User.objects.filter(name__contains=search_text,nodelist=select_node).values()
                else:
                    context['values'] = Vpn_User.objects.filter(name__contains=search_text, enable=user_enable, nodelist=select_node).values()


        context['search_text'] = search_text
        context['select_node'] = select_node

    context['num_list'], context['values'] = more_page(request, context['values'])
    for node in context['values']:
        node_list_id = []
        for node_ll in Vpn_User.objects.filter(id=node['id']).values('nodelist'):
            node_list_id.append(node_ll['nodelist'])
        node['nodelist'] = node_list_id

    return context

def vpn_node(request):
    if userauth(request) is False:
        path_info = request.META['PATH_INFO']
        return HttpResponseRedirect("/login?url=" + path_info)
    else:
        context = {}
        context['items'] = ["主机名", "IP地址", "端口","外网IP", "认证方式","在线", ""]
        context['values'] = Vpn_Node.objects.values()
        context['title'] = 'vpn_node'
        context['num_list'], context['values'] = more_page(request, context['values'])
        context['login_user'] = request.session.get('username')

        if request.POST:
            if 'del' in request.POST:
                request.POST['del']

                obj = Vpn_Node.objects.get(id=request.POST['del'])


                install_status=install_pptp(request,obj.ip, obj.port, obj.uid, obj.passwd, obj.ssh_key, False)
                print(install_status)

                sshkey_status=sshkey_copy(request,obj.ip, obj.port, obj.uid, obj.passwd, False)
                print(sshkey_status)
                write_log('系统日志', request.session.get('username'), '删除服务器', datetime.datetime.now(), Vpn_Node.objects.filter(id=request.POST['del']).values(), True)
                Vpn_Node.objects.filter(id=request.POST['del']).delete()
                try:
                    pass
                except:
                    context['add_node_stats'] = "获取数据失败！"
                finally:
                    context = dict(context.items() + get_vpn_node_search_values(request).items())
                return render(request, 'vpn_node.html', context)
            elif 'edit' in request.POST:
                obj = Vpn_Node.objects.get(id=request.POST['edit'])
                context['input_ip'] = obj.ip
                context['input_port'] = obj.port
                context['input_user'] = obj.uid
                context['input_passwd'] = obj.passwd
                context['input_wanip'] = obj.wanip
                if obj.ssh_key:
                    context['input_sshkey'] = "checked"

                context['hid'] = request.POST['edit']
                context['edit'] = request.POST['edit']
                context['status'] = obj.online

                return render(request, 'vpn_node.html', context)
            elif  'save' in request.POST:
                #print(request.POST)
                context['input_ip'] = request.POST['input_ip']
                context['input_port'] = request.POST['input_port']
                context['input_user'] = request.POST['input_user']
                context['input_passwd'] = request.POST['input_passwd']

                context['input_wanip']=request.POST['input_wanip']
                try:
                    input_sshkey = request.POST['input_sshkey']
                except:
                    input_sshkey = False
                else:
                    context['input_sshkey'] = "checked"
                    input_sshkey=True

                context['hid'] = request.POST['save']

                if len(request.POST['save'].strip()):
                    context['edit'] = request.POST['save']

                    old_ssh_key = Vpn_Node.objects.get(id=request.POST['save']).ssh_key
                    if old_ssh_key != input_sshkey:
                        sshkey_copy(request,request.POST['input_ip'], str(request.POST['input_port']),   request.POST['input_user'], request.POST['input_passwd'], input_sshkey)
                    #if input_sshkey:
                    #    context['input_passwd']=''
                    install_pptp(request,request.POST['input_ip'], str(request.POST['input_port']), request.POST['input_user'], context['input_passwd'], input_sshkey,True)
                    status, result = ssh_run(request.POST['input_ip'], str(request.POST['input_port']), request.POST['input_user'], context['input_passwd'], 'hostname', 'shell', input_sshkey)
                    if status:
                        Vpn_Node.objects.filter(id=request.POST['save']).update(name=request.POST['input_ip'] + ":" + request.POST['input_port'], hostname=result, ip=request.POST['input_ip'],\
                                                                                 port=request.POST['input_port'], uid=request.POST['input_user'], passwd=context['input_passwd'],wanip=context['input_wanip'],online=True,ssh_key=input_sshkey)
                    else:
                        Vpn_Node.objects.filter(id=request.POST['save']).update(name=request.POST['input_ip'] + ":" + request.POST['input_port'], ip=request.POST['input_ip'],\
                                                                                 port=request.POST['input_port'], uid=request.POST['input_user'], passwd=context['input_passwd'],wanip=context['input_wanip'], online=False,ssh_key=input_sshkey)
                    try:
                        context['status'] = status
                    except:
                        context['add_node_stats'] = "更新失败！"
                        return render(request, 'vpn_node.html', context)
                    else:
                        write_log('系统日志', request.session.get('username'), '更新服务器', datetime.datetime.now(),  Vpn_Node.objects.filter(id=request.POST['save']).values(), True)
                        context['add_node_stats'] = "更新成功！"
                else:
                    context['edit'] = 'add'
                    status, result = ssh_run(request.POST['input_ip'], str(request.POST['input_port']), \
                                     request.POST['input_user'], request.POST['input_passwd'], 'hostname','shell', False)

                    if status:
                        if Vpn_Node.objects.filter(hostname=result, ip=request.POST['input_ip'],port=request.POST['input_port']).count():
                            context['add_node_stats'] = "节点已经存在！"
                            return render(request, 'add_vpn_node.html', context)
                        else:

                            try:
                                if input_sshkey:
                                    sshkey_copy(request,request.POST['input_ip'], str(request.POST['input_port']),
                                                request.POST['input_user'], request.POST['input_passwd'], input_sshkey)
                                    #context['input_passwd'] = ''

                                install_pptp(request,request.POST['input_ip'], str(request.POST['input_port']),
                                             request.POST['input_user'], context['input_passwd'], input_sshkey, True)

                                obj=Vpn_Node.objects.create(name=request.POST['input_ip'] + ":" + request.POST['input_port'], hostname=result, ip=request.POST['input_ip'],\
                                                        port=request.POST['input_port'], uid=request.POST['input_user'], passwd=context['input_passwd'], wanip=context['input_wanip'],online=True,ssh_key=input_sshkey)
                                context['hid'] = obj.id
                            except:
                                context['add_node_stats'] = "添加失败！"
                            else:
                                context['add_node_stats'] = "添加成功！"
                                write_log('系统日志', request.session.get('username'), '添加服务器', datetime.datetime.now(),Vpn_Node.objects.filter(id=context['hid']).values(), True)
                            context['status'] = status
                    else:
                        context['add_node_stats'] = "节点不可用！"
                context = dict(context.items() + get_vpn_node_search_values(request).items())
                return render(request, 'vpn_node.html', context)
            elif 'search' in request.POST or 'page' in request.POST:
                context = dict(context.items() + get_vpn_node_search_values(request).items())
                return render(request, 'vpn_node.html', context)
        else:
            return render(request, 'vpn_node.html', context)

def get_vpn_node_search_values(request):
    #dictMerged1=dict(dict1.items()+dict2.items())
    context={}
    search_text = request.POST['search_text']
    online_select_val = request.POST['online_select_val']
    context['online_check_value'] = online_select_val

    # print(search_text,online_select_val)
    if len(search_text) == 0 and len(online_select_val) == 0:
        context['values'] = Vpn_Node.objects.values()
    else:
        if len(online_select_val) == 0:
            context['values'] = list(
                Vpn_Node.objects.filter(hostname__contains=search_text).values())
            for name_list in list(
                    Vpn_Node.objects.filter(name__contains=search_text).values()):
                if context['values'].count(name_list) == 0:
                    context['values'].append(name_list)
        else:
            if online_select_val == 'True':
                online_select_val = True
            else:
                online_select_val = False
            context['values'] = list(
                Vpn_Node.objects.filter(online=online_select_val, hostname__contains=search_text).values())
            for name_list in list(
                    Vpn_Node.objects.filter(online=online_select_val, name__contains=search_text).values()):
                if context['values'].count(name_list) == 0:
                    context['values'].append(name_list)
        context['search_text'] = search_text
    context['num_list'], context['values'] = more_page(request, context['values'])
    return context


def get_log_search_values(request):
    context={}
    if request.POST:
        context['start_time'] = request.POST['start_time']
        context['end_time'] = request.POST['end_time']
        search_text = request.POST['search_text']
        context['search_text'] = search_text
        log_status = request.POST['log_status']
        context['log_status'] = log_status
        log_type = request.POST['log_type']
        context['log_type'] = log_type
        if len(search_text) == 0 and  len( log_status) == 0 and  len( log_type) == 0 :  # start_time__icontains=context['start_time']
            context['values'] = Log.objects.filter(time__gte=context['start_time'],
                                                        time__lte=context['end_time']).order_by( '-time').values()

        else:
            if len(log_status) == 0:
                context['values'] = Log.objects.filter(time__gte=context['start_time'],
                                                       time__lte=context['end_time'],type__contains=log_type,content__contains=search_text).order_by('-time').values()
            else:
                if log_status == 'True':
                    log_status = True
                else:
                    log_status = False
                context['values'] = Log.objects.filter(time__gte=context['start_time'],
                                                       time__lte=context['end_time'],
                                                       content__contains=search_text,type__contains=log_type,status = log_status).order_by('-time').values()
    else:
        context['start_time'] = (datetime.datetime.now()).strftime("%Y-%m-%d 00:00:00")
        context['end_time'] = (datetime.datetime.now()).strftime("%Y-%m-%d 23:59:59")
        context['values'] = Log.objects.filter(time__gte=context['start_time'],
                                               time__lte=context['end_time']).order_by('-id').values()
    context['num_list'], context['values'] = more_page(request, context['values'])

    return context

def log(request):
    if userauth(request) is False:
        path_info = request.META['PATH_INFO']
        return HttpResponseRedirect("/login?url=" + path_info)
    else:
        context = {}
        context['items'] = ["日志类型", "用户","动作","时间", "执行状态", ""]
        context['values'] = Log.objects.values()
        context['type_list'] = Log.objects.values('type').distinct()
        context['title'] = 'vpn_log'
        context['login_user'] = request.session.get('username')
        if request.POST:
            #print(request.POST)
            if 'info' in request.POST:
                print(request.POST)
                try:
                    obj = Log.objects.get(id=request.POST['info'])
                    context['time'] = obj.time
                    context['type'] = obj.type
                    context['username'] = obj.username
                    context['content'] = obj.content
                    context['action'] = obj.action
                    context['status'] = obj.status
                except:
                    context['add_node_stats'] = "获取数据失败！"
                context['hid'] = request.POST['info']
                context = dict(context.items() + get_log_search_values(request).items())
                return render(request, 'log.html', context)
            elif 'search' in request.POST:
                context = dict(context.items() + get_log_search_values(request).items())

                return render(request, 'log.html', context)
            elif 'page' in request.POST:
                context = dict(context.items() + get_log_search_values(request).items())

                return render(request, 'log.html', context)
            else:
                return render(request, 'log.html', context)
        else:
            context = dict(context.items() + get_log_search_values(request).items())
            return render(request, 'log.html', context)


def check_user_vpn(request,userobj):
    timestr = datetime.datetime.now()
    node_list=Vpn_User.objects.filter(id=userobj.id).values('nodelist')
    print(timestr ,userobj.start_time,userobj.end_time )
    if timestr >= userobj.start_time and userobj.enable is False and timestr < userobj.end_time:
        Vpn_User.objects.filter(id=userobj.id).update(enable=True)
        write_log('系统日志', 'system', '启用账号', datetime.datetime.now(),  Vpn_User.objects.filter(id=userobj.id).values(), True)
        for node in node_list:
            print("enable vpn %s" % node['nodelist'])
            vpn_user_add_or_remove(request, userobj, node['nodelist'], True)

    if timestr >= userobj.end_time  and userobj.enable :
        Vpn_User.objects.filter(id=userobj.id).update(enable=False)
        write_log('系统日志','system', '禁用账号', datetime.datetime.now(),  Vpn_User.objects.filter(id=userobj.id).values(), True)

        for node in node_list:
            print("disable vpn %s" % node['nodelist'])
            vpn_user_add_or_remove(request, userobj, node['nodelist'], False)

def check_vpn_user(request):
    if request.POST:
        vpn_user_list = Vpn_User.objects.filter(disable_lease=False).all()
        print(vpn_user_list)
        thread_list = []
        for user in vpn_user_list:
            t2 = threading.Thread(target=check_user_vpn, args=(request, user))
            t2.start()
            thread_list.append(t2)
        for t in thread_list:
            t.join()
        return HttpResponse("over")
    else:
        vpn_user_list = Vpn_User.objects.filter(disable_lease=False).all()
        print(vpn_user_list)
        thread_list = []
        for user in vpn_user_list:
            t2 = threading.Thread(target=check_user_vpn, args=(request,user))
            t2.start()
            thread_list.append(t2)
        for t in thread_list:
            t.join()
        return HttpResponse("over")


def get_node_log(request,nodeobj):
    #nowtimestr=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    first_value=Log.objects.filter(node=nodeobj.id).order_by( '-time').first()
    #print(first_value.time)
    if first_value is None:
        #grep_cmd='sed -n "1,/'+nowtimestr+'/p" /var/log/pptpd.log'
        grep_cmd = "sed -n '1,/$/p' /var/log/pptpd.log"
    else:

        #grep_cmd = 'sed -n "/'+str(first_value.time)+'/,/' + nowtimestr + '/p" /var/log/pptpd.log '
        grep_cmd = 'sed -n "$(grep -n "' + str( first_value.time) + '" /var/log/pptpd.log |head -n 1 |awk -F ":" "{print \$1+1}" ),\$p" /var/log/pptpd.log '
    #print(grep_cmd)
    status, result=ssh_run(nodeobj.ip, nodeobj.port, nodeobj.uid, nodeobj.passwd, grep_cmd, 'shell', nodeobj.ssh_key)
    #print(status, result)
    if status:
        for line in result.split('\n'):
            value_list=line.split(',')
            if (len(value_list)) == 5 and len(value_list[0]) > 0 and Log.objects.filter(type='登陆日志',username=value_list[2],time=value_list[0],action=value_list[4],node=nodeobj.id,content=line,status=True).count() == 0:
                #2018-07-13 15:39:55,192.168.2.254,lilin5,192.168.100.207,logout'                
                Log.objects.create(type='登陆日志',username=value_list[2],time=value_list[0],action=value_list[4],node=nodeobj.id,content=line,status=True)
    #return status

def check_vpn_node(request):
    
    if request.POST:
        check_vpn_node_sshkey(request)
        return HttpResponse("over")
    else:
        check_vpn_node_sshkey(request)
        return HttpResponse("over")


def get_vpn_node_log(request):
    
    if request.POST:
        vpn_node_list = Vpn_Node.objects.all()
        thread_list = []
        for node in vpn_node_list:
            # thread_list.append(get_node_log(request,node))
            t2 = threading.Thread(target=get_node_log, args=(request, node))
            t2.start()
            thread_list.append(t2)
        for t in thread_list:
            t.join()
        return HttpResponse("over")

    else:
        vpn_node_list = Vpn_Node.objects.all()
        thread_list = []
        for node in vpn_node_list:
            #get_node_log(request, node)
            #thread_list.append(get_node_log(request,node))
            t2 = threading.Thread(target=get_node_log, args=(request, node))
            t2.start()
            thread_list.append(t2)
        for t in thread_list:
            t.join()
        return HttpResponse("over")
        

def check_vpn_node_sshkey(request):    
    os.popen("mkdir -p $HOME/.ssh;ssh-keygen -t dsa -P '' -f $HOME/.ssh/id_dsa")    
    
    home_path=os.popen("echo $HOME").read().split("\n")[0] 
    
    pub_path=home_path+'/.ssh/id_dsa.pub'
    dsa_path=home_path+'/.ssh/id_dsa'
    if os.path.exists(pub_path) and os.path.exists(dsa_path):
        pass
    else:
        os.popen("ssh-keygen -t dsa -P '' -f " + dsa_path).read()
        
    vpn_node_dict=Vpn_Node.objects.values()
    for nodelist in vpn_node_dict:        
        print("##################",nodelist)
        nodestats=sshkey_copy(request,nodelist['ip'], nodelist['port'],   nodelist['uid'], nodelist['passwd'], nodelist['ssh_key'])
        
        Vpn_Node.objects.filter(id=nodelist['id']).update(online=nodestats)
        
        
        
        

def svc_start_to_check_systemenv(): 
        
    os.popen("mkdir -p $HOME/.ssh;ssh-keygen -t dsa -P '' -f $HOME/.ssh/id_dsa")     
    home_path=os.popen("echo $HOME").read().split("\n")[0] 
    
    pub_path=home_path+'/.ssh/id_dsa.pub'
    dsa_path=home_path+'/.ssh/id_dsa'
    if os.path.exists(pub_path) and os.path.exists(dsa_path):
        pass
    else:
        os.popen("ssh-keygen -t dsa -P '' -f " + dsa_path).read()
     
    vpn_node_dict=Vpn_Node.objects.values()
    for nodelist in vpn_node_dict:        
        print("##################",nodelist)
        
    #print(env_dict)
    cron_delete('check_vpn')
    cron_delete('check_node')
    cron_delete('get_vpn_log')        
    
    s_url='http://localhost:'+sys.argv[2].split(':')[1]
    
    cmd_str="curl -s '"+s_url+"/check_vpn'" 
    cron_add('*/2 * * * *',cmd_str,'check_vpn', True)
    
    cmd_str="curl -s '"+s_url+"/check_node'" 
    cron_add('* * * * *',cmd_str,'check_node', True)
    
    cmd_str="curl -s '"+s_url+"/get_vpn_log'" 
    cron_add('*/5 * * * *',cmd_str,'get_vpn_log', True)    
        
    
if sys.argv[1] == 'runserver':
    if sys.platform != 'win32':
        svc_start_to_check_systemenv()

    



    
        
        
        
        
        
        
        
        
        
        
        
        
        