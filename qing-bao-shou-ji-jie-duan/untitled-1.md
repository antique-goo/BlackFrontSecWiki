# 基础信息收集

## 脚本语言信息收集

常见的脚本语言有PHP,ASP,ASPX,ASPX,JSP等

{% hint style="success" %}
* 首页文件,通常访问首页的时候会有后缀index.php,index.asp,index.aspx,index.jsp,index.do等
* 审查元素,通过审查可以看到请求头和响应头,可根据请求头或者响应头判断脚本语言
* robots.txt文件,robots.txt文件是每个网站的搜索引擎蜘蛛爬取指引文件
* 网站源码中,网站源码也会包含脚本语言文件
* 搜索引擎语法,比如：site:xxx.com inurl:php
* 报错法,如果一些网站没有设置404错误界面,或者设置了404错误界面,我们也可以根据500错误页面判断
* 等等...
{% endhint %}

## 数据库信息收集

常见的数据库有mysql,sqlserver,sqllite,oracle等,还有一些nosql数据库，例如：redis,mangodb,es等

### fuzz模糊测试，每种语言都有常见对应的数据库

```text
php---mysql
asp---sqlserver access
jsp---oracle
```

根据经验可以进行模糊测试

### 查看数据库开放端口

```text
Oracle---1521
MySQL---3306
SQL Server---1433
Sybase---5000
DB2---5000
PostgreSQL---5432
MongoDB---27017
Redis---6379
Memcached---11211
```

### 数据库报错信息

### 信息泄露文件,phpinfo.php

### 等等...

## 中间件信息收集

常见中间件有IIS,Apache,Nginx,Tomcat,jBoss,WebLogic,Lighttpd,IBM WebSphere,Tengine等等

{% hint style="success" %}
* 请求头响应头
* fuzz模糊测试，根据脚本语言和数据库来判断
* 报错信息
* 404错误信息
* http请求指纹
* 也可以根据旁站来判断
* 等等...漏洞扫描器或者爱站蜘蛛引擎通常更方便一些
{% endhint %}

## 操作系统信息收集

常见的操作系统就是linux,windows,mac

{% hint style="success" %}
* 最常见的方法就是大小写,linux是区分大小写的
* 指纹识别，nmap工具也会模糊测试出操作系统类型
* 也是fuzz模糊测试法，根据前面信息基本可以判断操作系统类型
* 端口测试法，linux经常会开放22端口,windows则会开放3389,也有可能改端口,通常nmap工具也会识别出来
* 等等...
{% endhint %}

## 后台信息收集

{% hint style="info" %}
* 枚举方法,通过御剑,dirb,dirsearch,dirmap等工具
* 信息泄露,有时robots.txt,sitemap.xml等文件会把后台写在里面
* 搜索引擎探测,例如：site:xxx.com 后台
* 蜘蛛爬取,burpsuite有蜘蛛爬取模块,可以查看爬取的地址
* 等等...取后台的方法比较多,有时候也不那么好取,根据实际情况来出发
{% endhint %}



