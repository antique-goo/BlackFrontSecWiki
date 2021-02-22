# OSINT Web信息收集

## 综合信息收集

[爱站网](https://www.aizhan.com/)

[站长工具](http://tool.chinaz.com/)

[semrush](https://www.semrush.com/)

[Alexa排名](http://www.alexa.cn)

## 网站备案及单位信息收集

[ICP/IP地址/域名信息备案管理系统](https://beian.miit.gov.cn/)

## WHOIS信息收集

[阿里云](https://whois.aliyun.com/whois/domain/)

[WHOIS365](https://www.whois365.com/cn/)

等...太多了

## 旁站信息收集

旁站查询接口，感谢原作

```text
http://cn.bing.com/search?q=ip%3A220.181.111.85
http://dns.aizhan.com/?q=www.baidu.com
http://domains.yougetsignal.com/domains.php?remoteAddress=lcx.cc
http://i.links.cn/sameip/61.164.241.103.html
http://ip.robtex.com/
http://rootkit.net.cn/index.aspx
```

查c段的话：

```text
http://c.wlan.im/
http://sameip.org/
http://tool.114la.com/sameip/
http://tool.chinaz.com/Same/
http://www.114best.com/ip/114.aspx?w=61.164.241.103
http://www.yougetsignal.com/tools/web-sites-on-web-server/，菜刀里面的。
```

域名解析IP地址历史记录查询：

小网站从无CDN到有CDN，会有一个IP变化的过程，netcraft.com会记录下来，也可以做参考：

```text
http://toolbar.netcraft.com/site_report?url=lcx.cc
```

域名Whois历史记录查询：

```text
http://www.benmi.com/whoishistory/
```

## C段信息收集

### NMAP

```text
nmap -sn -PE -n 10.60.17.1/24 
sn 不扫描端口
-PE ICMP扫描
-n 不进行dns解析
```

### masscan

```text
masscan -p 80 10.60.17.1/24 --rate 1000
-p：设置端口
--rate：发包速率
```

### ZMAP

### [Webscan](http://www.webscan.cc/)

## 子域名信息收集

Google Hacking 搜索引擎查询

### [DNS域传送漏洞](http://drops.xmd5.com/static/drops/tips-2014.html)

### 父站点爬取

### [IP反查](http://www.cnblogs.com/dongchi/p/4155368.html)

### [Forward-DNS](https://github.com/rapid7/sonar/wiki/Forward-DNS)

### 枚举法：子域名挖掘机

### HOST

### Dig

### [Dnsenum](https://tools.kali.org/information-gathering/dnsenum)

### [Dnsmap](https://tools.kali.org/information-gathering/dnsmap)

### [Fierce](https://tools.kali.org/information-gathering/fierce)

### [netcraft](http://toolbar.netcraft.com/site_report?url=xxx.com)

### 历史记录查询

### [DNSdumpster](https://dnsdumpster.com/)

### [SecurityTrails](https://securitytrails.com/)

### [DNSDB](https://dnsdb.io/zh-cn/)

## 真实IP信息收集

感谢原作

### 方法1:查询历史DNS记录

#### **1）查看 IP 与 域名绑定的历史记录，可能会存在使用 CDN 前的记录，相关查询网站有：**

```text
https://dnsdb.io/zh-cn/ #DNS查询
https://x.threatbook.cn/ #微步在线
http://toolbar.netcraft.com/site_report?url= #在线域名信息查询
http://viewdns.info/ #DNS、IP等查询
https://tools.ipip.net/cdn.php #CDN查询IP
```

#### **2）利用SecurityTrails平台，攻击者就可以精准的找到真实原始IP。他们只需在搜索字段中输入网站域名，然后按Enter键即可，这时“历史数据”就可以在左侧的菜单中找到。**

如何寻找隐藏在CloudFlare或TOR背后的真实原始IP

除了过去的DNS记录，即使是当前的记录也可能泄漏原始服务器IP。例如，MX记录是一种常见的查找IP的方式。如果网站在与web相同的服务器和IP上托管自己的

邮件服务器，那么原始服务器IP将在MX记录中。

### 方法2:查询子域名

毕竟 CDN 还是不便宜的，所以很多站长可能只会对主站或者流量大的子站点做了 CDN，而很多小站子站点又跟主站在同一台服务器或者同一个C段内，此时就可以通过查询子域名对应的 IP 来辅助查找网站的真实IP。

下面介绍些常用的子域名查找的方法和工具：

#### **1）微步在线\(https://x.threatbook.cn/\)**

上文提到的微步在线功能强大，黑客只需输入要查找的域名\(如baidu.com\)，点击子域名选项就可以查找它的子域名了，但是免费用户每月只有5次免费查询机会。

#### **2）Dnsdb查询法。\(https://dnsdb.io/zh-cn/\)**

黑客只需输入baidu.com type:A就能收集百度的子域名和ip了。

#### **3）Google 搜索**

Google site:baidu.com -www就能查看除www外的子域名

#### **4）各种子域名扫描器**

这里，主要为大家推荐子域名挖掘机和lijiejie的subdomainbrute\([https://github.com/lijiejie/subDomainsBrute](https://github.com/lijiejie/subDomainsBrute)\)

子域名挖掘机仅需输入域名即可基于字典挖掘它的子域名，

Subdomainbrute以windows为例，黑客仅需打开cmd进入它所在的目录输入Python subdomainbrute.py baidu.com --full即可收集百度的子域名，

注：收集子域名后尝试以解析ip不在cdn上的ip解析主站，真实ip成功被获取到。

### 方法3：网络空间引擎搜索法

常见的有以前的钟馗之眼，shodan，fofa搜索。以fofa为例，只需输入：title:“网站的title关键字”或者body：“网站的body特征”就可以找出fofa收录的有这些关键

字的ip域名，很多时候能获取网站的真实ip，

### 方法4:利用SSL证书寻找真实原始IP

使用给定的域名

假如你在xyz123boot.com上托管了一个服务，原始服务器IP是136.23.63.44。 而CloudFlare则会为你提供DDoS保护，Web应用程序防火墙和其他一些安全服务，以保护你的服务免受攻击。为此，你的Web服务器就必须支持SSL并具有证书，此时CloudFlare与你的服务器之间的通信，就像你和CloudFlare之间的通信一样，会被加密（即没有灵活的SSL存在）。这看起来很安全，但问题是，当你在端口443（[https://136.23.63.44:443](https://136.23.63.44:443)）上直接连接到IP时，SSL证书就会被暴露。

此时，如果攻击者扫描0.0.0.0/0，即整个互联网，他们就可以在端口443上获取在xyz123boot.com上的有效证书，进而获取提供给你的Web服务器IP。

目前Censys工具就能实现对整个互联网的扫描，Censys是一款用以搜索联网设备信息的新型搜索引擎，安全专家可以使用它来评估他们实现方案的安全性，而黑客则可以使用它作为前期侦查攻击目标、收集目标信息的强大利器。Censys搜索引擎能够扫描整个互联网，Censys每天都会扫描IPv4地址空间，以搜索所有联网设备并收集相关的信息，并返回一份有关资源（如设备、网站和证书）配置和部署信息的总体报告。

而攻击者唯一需要做的就是把上面用文字描述的搜索词翻译成实际的搜索查询参数。

xyz123boot.com证书的搜索查询参数为：parsed.names：xyz123boot.com

只显示有效证书的查询参数为：tags.raw：trusted

攻击者可以在Censys上实现多个参数的组合，这可以通过使用简单的布尔逻辑来完成。

组合后的搜索参数为：parsed.names: xyz123boot.com and tags.raw: trusted

Censys将向你显示符合上述搜索条件的所有标准证书，以上这些证书是在扫描中找到的。

要逐个查看这些搜索结果，攻击者可以通过单击右侧的“Explore”，打开包含多个工具的下拉菜单。What's using this certificate? &gt; IPv4 Hosts

此时，攻击者将看到一个使用特定证书的IPv4主机列表，而真实原始 IP就藏在其中。

你可以通过导航到端口443上的IP来验证，看它是否重定向到xyz123boot.com？或它是否直接在IP上显示网站？

使用给定的SSL证书

如果你是执法部门的人员，想要找出一个隐藏在cheesecp5vaogohv.onion下的儿童色情网站。做好的办法，就是找到其原始IP，这样你就可以追踪到其托管的服

务器，甚至查到背后的运营商以及金融线索。

隐藏服务具有SSL证书，要查找它使用的IPv4主机，只需将"SHA1 fingerprint"（签名

证书的sha1值）粘贴到Censys IPv4主机搜索中，即可找到证书，使用此方法可以轻松找到配置错误的Web服务器。

### 方法5:利用HTTP标头寻找真实原始IP

借助SecurityTrails这样的平台，任何人都可以在茫茫的大数据搜索到自己的目标，甚至可以通过比较HTTP标头来查找到原始服务器。

特别是当用户拥有一个非常特别的服务器名称与软件名称时，攻击者找到你就变得更容易。

如果要搜索的数据相当多，如上所述，攻击者可以在Censys上组合搜索参数。假设你正在与1500个Web服务器共享你的服务器HTTP标头，这些服务器都发送的是

相同的标头参数和值的组合。而且你还使用新的PHP框架发送唯一的HTTP标头（例如：X-Generated-Via：XYZ框架），目前约有400名网站管理员使用了该框

架。而最终由三个服务器组成的交集，只需手动操作就可以找到了IP，整个过程只需要几秒钟。

例如，Censys上用于匹配服务器标头的搜索参数是80.http.get.headers.server :，查找由CloudFlare提供服务的网站的参数如下：

80.http.get.headers.server:cloudflare

### 方法6:利用网站返回的内容寻找真实原始IP

如果原始服务器IP也返回了网站的内容，那么可以在网上搜索大量的相关数据。

浏览网站源代码，寻找独特的代码片段。在JavaScript中使用具有访问或标识符参数的第三方服务（例如Google Analytics，reCAPTCHA）是攻击者经常使用的方法。

以下是从HackTheBox网站获取的Google Analytics跟踪代码示例：

ga（'create'，'UA-93577176-1'，'auto'）; 可以使用80.http.get.body：参数通过body/source过滤Censys数据，不幸的是，正常的搜索字段有局限性，但你可以在Censys请求研究访问权限，该权限允许你通过Google BigQuery进行更强大的查询。

Shodan是一种类似于Censys的服务，也提供了http.html搜索参数。

搜索示例：[https://www.shodan.io/search?query=http.html%3AUA-32023260-1](https://www.shodan.io/search?query=http.html%3AUA-32023260-1)

### **方法7:使用国外主机解析域名**

国内很多 CDN 厂商因为各种原因只做了国内的线路，而针对国外的线路可能几乎没有，此时我们使用国外的主机直接访问可能就能获取到真实IP。

### 方法8:网站漏洞查找

```text
1）目标敏感文件泄露，例如：phpinfo之类的探针、GitHub信息泄露等。
2）XSS盲打，命令执行反弹shell，SSRF等。
3）无论是用社工还是其他手段，拿到了目标网站管理员在CDN的账号，从而在从CDN的配置中找到网站的真实IP。
```

### 方法9:网站邮件订阅查找

RSS邮件订阅，很多网站都自带 sendmail，会发邮件给我们，此时查看邮件源码里面就会包含服务器的真实 IP 了。

### 方法10：用 Zmap、masscan扫全网

需要找 xiaix.me 网站的真实 IP，我们首先从 apnic 获取 IP 段，然后使用 Zmap 的 banner-grab 扫描出来 80 端口开放的主机进行 banner 抓取，最后在 http-req

中的 Host 写 xiaix.me。

```text
#扫描全网，22端口，不扫exclude.txt 里面的IP，发包速率选择100000 ，结果输出到22-output.txt，不ping，不解析DNS。
masscan 0.0.0.0/0 -p 22 --excludefile exclude.txt --max-rate 100000 -oL 22-output.txt -Pn -n
#默认最大速率进行SYN扫描，现在最大2M速度进行扫描，22端口，探测目标上限数量为900，探测结果上限为100，不探测backlist里面的IP，扫描数据包的源端口设定为80-90，扫描目标为10.0.0.0/8 192.168.0.0/16
zmap -B 2M -p 22 -n 900 -N 100 -o 22-output.txt -b backlist.txt -s 80-90 10.0.0.0/8 192.168.0.0/16
#默认最大速率进行SYN扫描，现在最大2M速度进行扫描，22端口，探测目标上限数量为900，探测结果上限为100，不探测backlist里面的IP，扫描数据包的源端口设定为80-90，使用udp扫描，全网扫描
zmap -B 2M -p 22 -n 900 -N 100 -o 22-output.txt -b backlist.txt -s 80-90 -M udp 0.0.0.0/0
```

```text
http://ftp.apnic.net/stats/apnic/delegated-apnic-latest	#全网IP
http://www.ipdeny.com/ipblocks/	#全网IP
./zgrab -input-file=hk.res -senders=2000 -data-"./http-reg" | grep -E 'memberlogin' >> x.txt
```

#### Zmap

```text
zmap -w CN.txt -p 80 -o 80.txt
cat http-req#编辑一下如下内容
#GET / HTTP/1.1
#Host: www.abc.com
cat 80.txt | banner-grep-tcp -c 1500 -d http-req -f assic -p 80 -t 30 -r 30 >result.txt
grep "xxx.com" result.txt | wc -l
```

#### Zgrab

```text
cat *.zone | zmap -p 80 -B 200M -o world.80
cat cn.80 | ./zgrab --port 80 -http-user-agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.95 Safari/537.36" -timeout=30 -senders=2000 -data="./http-req" --output-file=cnresult.txt
cat cn.443 | ./zgrab --port 443 --tls -http-user-agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.95 Safari/537.36" -timeout=30 -senders=2000 -data="./http-req" --output-file=cnresult.txt
cat cnresult.txt |grep -E "关键词" > cnpr.txt

sed -e '/aliyungf/d' cnpr.txt > cn.target 
sed -e '/cfduid/d' cnpr.txt > cn.target
```

#### 当然自动化的工具也有人写好了，w8Fuckcdn

```text
https://github.com/boy-hack/w8fuckcdn
usage: python get_ips.py -d baidu.com
```

### 方法11：F5 LTM解码法

当服务器使用F5 LTM做负载均衡时，通过对set-cookie关键字的解码真实ip也可被获取，例如：Set-Cookie:

BIGipServerpool\_8.29\_8030=487098378.24095.0000，先把第一小节的十进制数即487098378取出来，然后将其转为十六进制数1d08880a，接着从后至前，以

此取四位数出来，也就是0a.88.08.1d，最后依次把他们转为十进制数10.136.8.29，也就是最后的真实ip。

### 方法12：错误配置及网站敏感文件

错误的配置：有些域名只配置了www而没有配置主域名，我们可以通过访问主域名来获取真实ip

网站敏感文件：有些敏感文件可以泄露真实IP的，比如phpinfo.php

## 邮件系统信息收集

## WEB敏感文件信息收集

感谢原作，很实用，还有很多需要实战积累

.hg源码泄漏

漏洞成因：

hg init的时候会生成.hg

e.g.[http://www.example.com/.hg/](http://www.example.com/.hg/)

漏洞利用：

工具：dvcs-ripper

rip-hg.pl -v -u [http://www.example.com/.hg/](http://www.example.com/.hg/)

.git源码泄漏

漏洞成因：

在运行git init初始化代码库的时候，会在当前目录下面产生一个.git的隐藏文件，用来记录代码的变更记录等等。在发布代码的时候，把.git这个目录没有删除，直

接发布了。使用这个文件，可以用来恢复源代码。

e.g. [http://www.example.com/.git/config](http://www.example.com/.git/config) 漏洞利用：

工具：

GitHack

GitHack.py [http://www.example.com/.git/](http://www.example.com/.git/)

dvcs-ripper

rip-git.pl -v -u [http://www.example.com/.git/](http://www.example.com/.git/)

.DS\_Store文件泄漏

漏洞成因:

在发布代码时未删除文件夹中隐藏的.DS\_store，被发现后，获取了敏感的文件名等信息。

漏洞利用:

[http://www.example.com/.ds\_store](http://www.example.com/.ds_store)

注意路径检查

工具：

dsstoreexp

python ds\_store\_exp.py [http://www.example.com/.DS\_Store](http://www.example.com/.DS_Store)

网站备份压缩文件

在网站的使用过程中，往往需要对网站中的文件进行修改、升级。此时就需要对网站整站或者其中某一页面进行备份。当备份文件或者修改过程中的缓存文件因为

各种原因而被留在网站web目录下，而该目录又没有设置访问权限时，便有可能导致备份文件或者编辑器的缓存文件被下载，导致敏感信息泄露，给服务器的安全

埋下隐患。

漏洞成因及危害:

该漏洞的成因主要有以下两种：

服务器管理员错误地将网站或者网页的备份文件放置到服务器web目录下。

编辑器在使用过程中自动保存的备份文件或者临时文件因为各种原因没有被删除而保存在web目录下。

漏洞检测:

该漏洞往往会导致服务器整站源代码或者部分页面的源代码被下载，利用。源代码中所包含的各类敏感信息，如服务器数据库连接信息，服务器配置信息等会因此

而泄露，造成巨大的损失。被泄露的源代码还可能会被用于代码审计，进一步利用而对整个系统的安全埋下隐患。

```text
.rar.zip.7z.tar.gz.bak.swp.txt.html
```

SVN导致文件泄露

Subversion，简称SVN，是一个开放源代码的版本控制系统，相对于的RCS、CVS，采用了分支管理系统，它的设计目标就是取代CVS。互联网上越来越多的控制

服务从CVS转移到Subversion。

Subversion使用服务端—客户端的结构，当然服务端与客户端可以都运行在同一台服务器上。在服务端是存放着所有受控制数据的Subversion仓库，另一端是

Subversion的客户端程序，管理着受控数据的一部分在本地的映射（称为“工作副本”）。在这两端之间，是通过各种仓库存取层（Repository Access，简称RA）

的多条通道进行访问的。这些通道中，可以通过不同的网络协议，例如HTTP、SSH等，或本地文件的方式来对仓库进行操作。

e.g.[http://vote.lz.taobao.com/admin/scripts/fckeditor.266/editor/.svn/entries](http://vote.lz.taobao.com/admin/scripts/fckeditor.266/editor/.svn/entries)

漏洞利用:

工具：

dvcs-ripper

rip-svn.pl -v -u [http://www.example.com/.svn/](http://www.example.com/.svn/)

Seay-Svn

WEB-INF/web.xml泄露

WEB-INF是Java的WEB应用的安全目录。如果想在页面中直接访问其中的文件，必须通过web.xml文件对要访问的文件进行相应映射才能访问。

WEB-INF主要包含一下文件或目录：

/WEB-INF/web.xml：Web应用程序配置文件，描述了 servlet 和其他的应用组件配置及命名规则。

/WEB-INF/classes/：含了站点所有用的 class 文件，包括 servlet class 和非servlet class，他们不能包含在 .jar文件中

/WEB-INF/lib/：存放web应用需要的各种JAR文件，放置仅在这个应用中要求使用的jar文件,如数据库驱动jar文件

/WEB-INF/src/：源码目录，按照包名结构放置各个java文件。

/WEB-INF/database.properties：数据库配置文件

漏洞成因：

通常一些web应用我们会使用多个web服务器搭配使用，解决其中的一个web服务器的性能缺陷以及做均衡负载的优点和完成一些分层结构的安全策略等。在使用

这种架构的时候，由于对静态资源的目录或文件的映射配置不当，可能会引发一些的安全问题，导致web.xml等文件能够被读取。

漏洞检测以及利用方法：

通过找到web.xml文件，推断class文件的路径，最后直接class文件，在通过反编译class文件，得到网站源码。

一般情况，jsp引擎默认都是禁止访问WEB-INF目录的，Nginx 配合Tomcat做均衡负载或集群等情况时，问题原因其实很简单，Nginx不会去考虑配置其他类型引

擎（Nginx不是jsp引擎）导致的安全问题而引入到自身的安全规范中来（这样耦合性太高了），修改Nginx配置文件禁止访问WEB-INF目录就好了： location ~

^/WEB-INF/\* { deny all; } 或者return 404; 或者其他！

CVS泄漏

漏洞利用

测试的目录

[http://url/CVS/Root](http://url/CVS/Root) 返回根信息

[http://url/CVS/Entries](http://url/CVS/Entries) 返回所有文件的结构

取回源码的命令

bk clone [http://url/name](http://url/name) dir

这个命令的意思就是把远端一个名为name的repo clone到本地名为dir的目录下。

查看所有的改变的命令，转到download的目录

bk changes

Bazaar/bzr

工具：

dvcs-ripper

rip-bzr.pl -v -u [http://www.example.com/.bzr/](http://www.example.com/.bzr/)

工具推荐

Bitkeeper

weakfilescan

参考 [https://zhuanlan.zhihu.com/p/21296806](https://zhuanlan.zhihu.com/p/21296806) [http://www.s2.sshz.org/post/source-code-leak/](http://www.s2.sshz.org/post/source-code-leak/)

## WAF防火墙信息收集

Waf识别大多数是根据header来判断头信息来判断的

### [Whatwaf](https://github.com/Ekultek/WhatWaf)

### [wafw00f](https://github.com/EnableSecurity/wafw00f)

### sqlmap

### Nmap

```text
nmap -p 80 --script http-waf-detect.ns xxx.com
```

## 历史漏洞信息收集

### 乌云

### CNVD

### 搜索引擎

### 知道创宇漏洞库

### exploit-db

## 端口信息收集

### Nmap

```text
nmap -sT -sV -Pn -v IP
nmap -sS -p 1-65535 -v IP
```

## Google Hacking搜索引擎收录信息收集

#### [在线google hacking](https://pentest-tools.com/information-gathering/google-hacking)

## 物理路径信息收集

网站敏感文件之前讲过了敏感文件都有哪些

报错点

可以通过后台获取

web中间件报错信息，例如 IIS

搜索引擎查找error warning mysql等信息

## CMS指纹信息收集

云悉资产

[在线cms指纹识别](http://whatweb.bugscaner.com/look/)

[cmscan](https://github.com/cuijianxiong/cmscan)

[cmsIdentification](https://github.com/theLSA/cmsIdentification/)

[在线cms识别](https://pentest.gdpcisa.org/whatcms)

[onlinetools](https://github.com/iceyhexman/onlinetools)

whatweb

[godeye](https://www.godeye.vip/)

## 常见信息泄露

```text
用户目录下的敏感文件
.bash_history.zsh_history.profile.bashrc.gitconfig.viminfopasswd
应用的配置文件
/etc/apache2/apache2.conf/etc/nginx/nginx.conf
应用的日志文件
/var/log/apache2/access.log/var/log/nginx/access.log
站点目录下的敏感文件
.svn/entries.git/HEADWEB-INF/web.xml.htaccess
特殊的备份文件
.swp.swo.bakindex.php~...
Python的Cache
__pycache__\__init__.cpython-35.pyc
弱密码
位数过低
字符集小
为常用密码
个人信息相关
手机号
生日
姓名
用户名
使用键盘模式做密码
敏感文件泄漏
.git
.svn
数据库
Mongo/Redis等数据库无密码且没有限制访问
加密体系
在客户端存储私钥
三方库/软件
公开漏洞后没有及时更新
```

