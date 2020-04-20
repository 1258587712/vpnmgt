#!/bin/bash
workdir=$(dirname ${0})
version=`rpm -q centos-release |awk -F '-' '{print $3}'`
#echo $workdir $0
declare -A project_name
if [ "$workdir" == "." ] ;then
    workdir=$(pwd)
    chmod a+x ${workdir}/$0
else
    chmod a+x $0
fi


#echo ${workdir}/$0
init_project(){ 
tmpdir='/opt/soft/'    
[ -e ${tmpdir} ] && cd ${tmpdir} || mkdir -p ${tmpdir} && cd ${tmpdir} 

#echo "#######zip wget curl gcc"
#yum install -y vim wget curl python-setuptools gcc unzip zlib zlib-devel crontabs && service crond start 

yum install -y wget  

#####安装Python-2.7.15
echo "#######Python-2.7.15"
[ "$(/usr/bin/python -V 2>&1  |cut -d' ' -f2 |cut -d. -f1-2)" != "2.7" ] && (([ ! -e Python-2.7.15.tgz ] && (wget -q https://www.python.org/ftp/python/2.7.15/Python-2.7.15.tgz || wget -q https://www.python.org/ftp/python/2.7.15/Python-2.7.15.tgz --no-check-certificate) ) && tar zxf Python-2.7.15.tgz && cd Python-2.7.15 && ./configure && make && make install && mv -f /usr/bin/python /usr/bin/python2.6 && ln -sf /usr/local/bin/python2.7 /usr/bin/python && sed -i 's/^#!\/usr\/bin\/python$/#!\/usr\/bin\/python2.6/g' /usr/bin/yum ) 

#yum install -y python-setuptools  

([ ! -e /usr/local/bin/pip -a ! -e /usr/bin/pip ] && (wget https://bootstrap.pypa.io/get-pip.py -O get-pip.py && python get-pip.py )) && \    
pip install django==1.9.7  && \
pip install pymysql && \
pip install paramiko && \
pip install python-crontab


#pip install pexpect && \
#pip install dwebsocket==0.4.2 && \
#pip install chardet && \
#pip install psutil 

####echo "#######mysql-community-server" 
####
####[ ! -e /usr/bin/mysql -a ! -e /usr/local/mysql ] && (([ ${version} -eq 6 ] && rpm -ivh http://repo.mysql.com/mysql-community-release-el6-5.noarch.rpm  || rpm -ivh http://dev.mysql.com/get/mysql-community-release-el7-5.noarch.rpm ) && yum -y install mysql-community-server && chkconfig mysqld on && service mysqld start ) 

####mysql -e "CREATE DATABASE IF NOT EXISTS ${project_name} COLLATE = 'utf8_general_ci' CHARACTER SET = 'utf8';
####GRANT ALL ON *.* TO '${project_name}'@'%' IDENTIFIED BY '${project_name}';
####GRANT ALL ON *.* TO '${project_name}'@'localhost' IDENTIFIED BY '${project_name}';
####show databases;"  

#GRANT ALL ON *.* TO 'vpnmgt'@'%' IDENTIFIED BY 'vpnmgt';
#GRANT ALL ON *.* TO 'vpnmgt'@'localhost' IDENTIFIED BY 'vpnmgt';


\cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
   
}



start_app(){
if [ $(netstat -lntp |grep -c ':8080 ') -eq 0 ] ;then 
    echo "Port ${1} is starting ..."
    python ${workdir}/manage.py runserver 0.0.0.0:${1}
else
    echo "Port ${1} is started" && exit 1
    
fi
}
stop_app(){
    
    
pid=`echo $(ps -ef |grep "${workdir}/manage.py runserver 0.0.0.0:${1}"  |grep -v grep |awk '{print $2}')`            

[ ${#pid} -gt 0 ] && (echo "Port ${1} is stopping ..." && kill -9 $pid >/dev/null 2>&1)  || echo "Port ${1} is stopped"

    
}

update_db(){
echo "Update database ..."
python ${workdir}/manage.py makemigrations --merge || python ${workdir}/manage.py makemigrations 
python ${workdir}/manage.py migrate

}

if [ $# -eq 2 ];then
    #cd ${workdir}
    #echo $workdir
    project_name=$(grep settings  ${workdir}/manage.py |sed 's#"##g' |sed 's# ##g' |cut -d ',' -f 2 |cut -d '.' -f 1)
    
    if [ ! -e /usr/bin/mysql ] \
	&& [ ! -e /usr/local/mysql ];then
        cron_install
    fi
    
    case $2 in        
        init)            
            #if [ $(mysql -e 'show databases;' |grep -c "^${project_name}$") -eq 0 ];
			if [ ! -e /usr/local/bin/pip -a ! -e /usr/bin/pip ]; then
                echo "Start to init "
                init_project 
                update_db 
            else
                echo "Install Success"
            fi
        ;;         
        start)            
            #if [ $(mysql -e 'show databases;' |grep -c "^${project_name}$") -eq 0 ];
			if [ ! -e /usr/local/bin/pip -a ! -e /usr/bin/pip ]; then            
                init_project				
                update_db
            fi            
            start_app ${1}            
        ;;
        update)
            if [ ! -e /usr/local/bin/pip -a ! -e /usr/bin/pip ]; then            
                echo "Start to install"
                init_project
				
                update_db 
            else
                update_db
            fi            
        ;;
        stop)        
            stop_app ${1}
        ;;
        restart) 
            stop_app ${1}
            sleep 1
            start_app ${1}          
        ;;
        *)        
            echo -e "Usage:\n$0 [init|start|stop|restart]"
        ;;
    esac   
else
    echo -e "Usage:\n$0 [port] [init|start|stop|restart]"
fi

