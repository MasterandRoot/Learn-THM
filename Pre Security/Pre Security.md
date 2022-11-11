# 安全入门
## 网络安全简介
### 进攻性安全简介
- 破解你的第一台机器
  - 目标网站FakeBank 
  - gobuster目录扫描
    - `gobuster -u http://fakebank.com -w wordlist.txt dir`
    - `-u` 设置目标网址，`-w` 设置字典
- 进攻性安全
- 进攻性安全职业
  - 渗透测试员

### 防御性安全简介
  - SOC 安全运维中心
  - DFIR 数字取证和数字响应
### 安全职业
  - 进攻为主
  - 防御为主

## 网络基础
### 什么是网络
- 什么是网络
- 什么是互联网
- 识别网络上的设备
  - IP
  - MAC
    - MAC欺诈
- ping
  - 使用ICMP协议
### 局域网介绍
- 局域网拓扑
    - 星型拓扑
    - 总线拓扑
    - 环形拓扑
  - 交换机
  - 路由器
- 子网
  - IP地址
    - 网络地址
    - 主机地址
    - 默认网关
- ARP协议
  - 该协议允许MAC地址与IP地址关联
  - ARP请求，广播
    - SRC MAC A
    - DST MAC FF:FF:FF:FF:FF:FF
    - MSG：Who has IP Address XXX.XXX.XXX.XXX
  - ARP响应
    - SRC MAC B
    - DST MAC A
    - MSG：I Have IP Address XXX.XXX.XXX.XXX
- DHCP协议
  - 动态主机配置协议
  - 流程
    - DHCP Discover 设备查看网络上是否有DHCP服务器
    - DHCP Offer DHCP服务器回复可用IP
    - DHCP Request 设备回复确认使用IP
    - DHCP ACK 服务器回复确认
### OSI模型
- 什么是OSI模型
  - 封装（encapsulation）
  - 7层结构
    - 应用层（Application）
    - 表示层（Presentation）
    - 会话层（Session）
    - 传输层（Transport）
    - 网络层（Network）
    - 数据链路层（Data link）
    - 物理层（Physical）
- 应用层（Application）
  - GUI
  - 浏览器等
  - DNS
- 表示层（Presentation）
  - 开始进行标准化的层，充当第7层的数据转换器（Translator），进行格式化
  - 数据加密等安全功能（HTTPS）在该层实现
- 会话层（Session）
  - 一旦数据在表示层被正确转换或格式化，会话层将建立与另一台计算机的连接
  - 建立连接时，会创建会话
  - 会话层会将要发送的数据分解为更小的数据包
  - 会话是独一无二的
- 传输层（Transport）
  - 传输层在设备之间发送数据，基于 `TCP` 和 `UDP` 协议
  - TCP（传输控制协议）
    - 可靠性，在发送和接受数据的时候保证两个设备之间的稳定连接
    - 错误检查，保证会话层中的小块数据包被接收方以相同的顺序重写组合
  - UDP（用户数据报协议）
    - ARP、DHCP使用UDP协议
- 网络层（Network）
  - 路由协议
    - OSPF (开放式最短路径优先)
    - RIP (路由信息协议)
  - 在这一层，一切都通过 IP 地址处理，例如 192.168.1.100。能够使用 IP 地址传送数据包的设备（例如路由器）被称为第 3 层设备——因为它们能够在 OSI 模型的第三层工作。
- 数据链路层（Data link）
  - 数据链路层专注于传输的物理寻址。它从网络层接收数据包（包括远程计算机的 IP 地址），并添加接收端点的物理MAC地址 。每台支持网络的计算机内部都有一个网络接口卡 ( NIC ) ，它带有一个唯一的MAC地址来识别它。  

  - MAC地址由制造商设置并直接烧录到卡中；它们无法更改——尽管它们可以被欺骗。当信息通过网络发送时，它实际上是用于确定将信息准确发送到何处的物理地址。

  - 此外，以适合传输的格式呈现数据也是数据链路层的工作。
- 物理层（Physical）
  - 这一层引用了网络中使用的硬件的物理组件。
  - 设备使用电信号在二进制编号系统（1 和 0）中相互传输数据。

### 数据包（Packet）和帧（Frame）
- 什么是数据包和帧
  - 帧 存在于数据链路层，没有IP地址信息
  - 数据包根据不同的协议类型有不同的结构，以`Internet Protocol`为例：
    - Time to live
    - Checksum
    - Source Address
    - Destination Address 
- TCP/IP 三次握手
  - TCP/IP协议具有四层结构
    - 应用层
      - HTTP（80）、HTTPS（443）、FTP（20/21）、DNS(53)
    - 传输层
      - TCP、UDP
    - 网络层
      - ICMP、IP、ARP
    - 物理层
      - MAC子层协议
  - TCP协议
    - TCP协议是基于连接的，这意味着TCP必须在发送数据之前在两个设备之间建立连接
    - 常见的标头
      - Source Port
      - Destination Port
      - *Source IP*
      - *Destination IP*	
      - Sequence Number（序列号）
      - Acknowledgement Number（确认号）
      - Flag（标志） 6位组成 
        - URG 紧急，若置为1，则表示携带的是紧急信息
        - ACK 应答，若置为1，则Acknowledgement Number有效
        - PSH 推送，若置为1，则接收方需尽快传递所有数据给应用
        - RST 复位，若置为1，则表示发出一个重置 TCP 连接的请求
        - SYN 同步，若置为1，则表示在发起连接时同步
        - FIN 终止，若置为1，则表示终止会话
        ```
        Urgent (URG): If the first bit is set, an urgent message is being carried
        Acknowledgment (ACK): If the second bit is set, the acknowledgment number is valid
        Push (PSH): If the third bit is set, it is notification from the sender to the receiver that the receiver should pass all the data to the application quickly
        Reset (RST): If the fourth bit is set, it signals a request to reset the TCP connection.
        Synchronizing (SYN): The fifth bit of the flag field of the packet is set to synchronize when initiating a connection
        End (FIN): The sixth bit is set to terminate a connection
        ```
    - TCP三次握手
      1. SYN (SeqN = x)
      2. SYN/ACK(SeqN = y ; AckN = x + 1)
      3. ACK(AckN = y + 1)
    - TCP四次挥手
      1. FIN (SeqN = x)
      2. ACK (AckN = x + 1)
      3. FIN (SeqN = y)
      4. ACK (AckN = y + 1)
- UDP/IP
  - UDP协议常见的标头
    - TTL 生存时间
    - Source Port
    - Destination Port
    - Source IP
    - Destination IP

- 端口101 
  - 1-1024端口为公共端口
    - FTP 20/21 20为传输数据端口，21为管理控制端口
    - SMP 445
    - RDP 3389
    - ...
    - [Port 0 - 1024](http://www.vmaxx.net/techinfo/ports.htm)
### 网络扩展知识
- 端口转发
  1. 一台服务器 192.168.1.10
  2. 网络公网IP 82.64.3.56
  3. 另一网络想访问服务器80端口
  4. 在***路由器***上配置端口转发
- 防火墙
  - 防火墙可分为两类
    - Stateful 
      - 基于整个连接判断分析行为
    - Stateless
      - 基于单个数据包，匹配规则
- VPN基础
  - 常见的VPN技术
    - PPP
    - PPTP
    - IPSec  
- LAN网络设备
  - Router(路由器)，OSI的网络层
  - Switch(交换机)，OSI的数据链路层和网络层
    - 二层交换机
    - 三层交换机
      - VLAN技术允许将网络中的设备虚拟拆分
- 网络模拟器
## Web的工作原理
### DNS详解
- 什么是DNS(域名系统)
- Domain的层次结构
  - Root Domain
  - TLD(顶级域名)
    - gTLD 通用顶级域名
      - .com 商业
      - .org 组织
      - .edu 教育 
      - .gov 政府
    - ccTLD 国家代码顶级域名
      - .ca
      - .cn
    - [TLD完整列表](https://data.iana.org/TLD/tlds-alpha-by-domain.txt)
  - 二级域名
    - 以 tryhackme.com 为例，`.com` 为TLD，`tryhackme`为二级域名
    - 二级域名限制为63个字符+TLD，只能使用a-z 0-9和连字符。
  - 子域名      
    - 以 admin.tryhackme.com 为例，`admin` 是子域。子域名的创建限制与二级域名相同，限制为 63 个字符，并且只能使用 az 0-9 和连字符（不能以连字符开头或结尾，也不能有连续的连字符）。
    - 可以使用多个以句点分隔的子域来创建更长的名称，例如 jupiter.servers.tryhackme.com。但长度必须保持在 253 个字符或更少。创建的子域数量没有限制。
- 记录类型
  - A
    - IPv4 地址
  - AAAA
    - IPv6 地址
  - CNAME
    - 解析到另一个域名
    - 例如有子域名 store.tryhackme.com，它返回一个 CNAME 记录 shop.shopify.com。
    - 然后将向 shop.shopify.com 发出另一个 DNS 请求以计算出 IP 地址。
  - MX
    - 电子邮件的服务器地址
    - MX记录允许设置一个优先级，当多个邮件服务器可用时，会根据该值决定投递邮件的服务器
  - TXT
- DNS请求
  - 几种DNS服务器类型
    - 权威服务器
    - TLD服务器
    - 根服务器
    - 递归服务器
### HTTP详解
- 什么是HTTP(S)?
- 请求和响应
  - URL
  ![URL详解](https://static-labs.tryhackme.cloud/sites/howhttpworks/newurl.png)

  - 请求示例
  ```
  GET / HTTP/1.1
  Host: tryhackme.com
  User-Agent: Mozilla/5.0 Firefox/87.0
  Referer: https://tryhackme.com/
  ```
  - 响应示例
  ```
  HTTP/1.1 200 OK
  Server: nginx/1.15.8
  Date: Fri, 09 Apr 2021 13:34:03 GMT
  Content-Type: text/html
  Content-Length: 98

  <html>
  <head>
    <title>TryHackMe</title>
  </head>
  <body>
    Welcome To TryHackMe.com
  </body>
  </html>
  ```
- 请求方法
  - POST、GET、PUT、DELETE
- 响应状态码
  - 200 请求完成
  - 201 已创建完成
  - 301 永久重定向
  - 302 临时重定向
  - 401 未授权访问（登录）
  - 403 无权访问
  - 404 页面不存在
  - 405 不允许的方法 
    - 向/create-account 发送了一个 GET 请求，而它原本期望一个 POST 请求
  - 500 服务器内部错误
  - 503 服务器不可用，超载或停机维护

- Headers
  - 请求
    - Host: 一些网络服务器托管多个网站，因此通过提供主机标头表明需要哪个网站，否则只会收到服务器的默认网站
    - User-Agent: 浏览器软件和版本号
    - Content-Length: 数据包长度
    - Accept-Encoding: 支持哪些压缩方法
    - Cookie: Data sent to the server to help remember your information 
  - 响应
    - Set-Cookie: Information to store which gets sent back to the web server on each request 
    - Cache-Control: 浏览器缓存时间
    - Content-Type: 表示后面的文档属于什么MIME类型
    - Content-Encoding: 使用的压缩算法

- Cookies
  ![cookies详解](https://static-labs.tryhackme.cloud/sites/howhttpworks/cookie_flow.png)

### Website工作原理
- HTML
- Javascript
- 敏感数据暴露
  - 查看网页源代码
- HTML注入
### Web汇总
- 在浏览器请求网页的时候，主要流程:
  ![请求网页流程](https://static-labs.tryhackme.cloud/sites/puttingittogether/puttingitalltogether.png)

- Web组件
  - 负载均衡器
    - 确保网站高流量时可以处理负载
    - 在服务器无响应时提供故障转移
    - 当您使用负载均衡器请求网站时，负载均衡器将首先接收您的请求，然后将其转发到其后面的多个服务器之一。
    - 负载均衡器使用不同的算法来帮助它决定哪个服务器最适合处理请求。
      - 轮询。将请求按顺序轮流地分配到后端服务器上，它均衡地对待后端的每一台服务器，而不关心服务器实际的连接数和当前的系统负载。
      - 加权。它检查服务器当前正在处理多少请求并将其发送到最不繁忙的服务器。
    - 负载均衡器还会对每台服务器执行定期检查，以确保它们正常运行；这称为健康检查(health check)。如果服务器没有正确响应或没有响应，负载均衡器将停止发送流量，直到它再次正确响应。
  - CDN
    - 允许托管静态文件,例如JS、CSS、图像、视频等,并将它们托管在全球数千台服务器上。
  - 数据库
  - WAF(Web应用防火墙)
- Web服务器的工作原理
  - Web服务器
    - 软件，常见有Apache、Nginx、IIS、NodeJS等。
    - Nginx和Apache在Linux上默认位置`/var/www/html`
    - IIS在Windows上的默认位置`C:\inetub\wwwroot`
  - 虚拟主机
    - Web服务器可以托管多个不同域名的网站,为此使用虚拟主机。
    - 服务器通过检查HTTP标头请求主机名,将其与虚拟主机匹配。
      - 虚拟主机只是基于文本的匹配文件。
      - one.com映射到 `/var/www/website_one`，two.com映射到 `/var/www/website_two`
    - Web服务器上托管的不同网站数量没有限制。
  - 静态网页和动态网页
  - 脚本和后端语言
    - PHP、Python等

- 流程小结
  1. 浏览器里请求example.com
  2. 检查本地IP缓存
  3. 检查递归DNS服务器
  4. 请求根服务器去查询权威服务器
  5. 权威服务器提供IP地址
  6. 请求通过WAF
  7. 请求通过负载均衡
  8. 连接Web服务器的80或443端口
  9. Web服务器收到(receives)GET请求
  10. Web应用连接数据库
  11. 浏览器渲染收到的HTML文件
## Linux基础
### Linux基础 part.1
- Linux背景
- Linux终端(terminal)命令
  - `echo`
  - `whoami`
- 文件系统常见命令
  - `ls`
  - `cd`
  - `cat` 查看文件内容
    - `cat example.txt`
  - `pwd` 当前工作路径
- 搜索文件
  - `find`
    - `find -name password.txt`
    - `find -name *.txt`
  - `grep` 查询内容
    - `wc` 计算字数、行数等
    - `grep "126.64.33.54" access.log`
- shell运算符
  - `&` 在终端后台运行命令
    - 例如在复制大文件的时候，可以后台运行
  - `&&` 组合多个命令
    - `command1 && command2`
    - 只有在conmmand1运行成功时，才会运行command2
  - `>` 重定向，从命令中获取输出并定向到其他地方
    - `echo hey > 1.txt`
  - `>>` 重定向，但不会覆盖原文件
    - `echo hello >> 1.txt`
### Linux基础 part.2
- 命令参数
  - `command --help`
  - `man command` 查看手册页
- 文件系统进阶命令
  - `touch` 创建文件
  - `mkdir` 创建文件夹
  - `cp` 复制
  - `mv` 剪切，重命名
  - `rm` 删除
    - `rm -R` 删除文件夹
  - `file` 确定文件类型
- 权限(Permissions)101
  - `su -l user` 
    - 这个参数加了之后，就好像是重新 login 为该使用者一样，大部份环境变数（HOME SHELL USER等等）都是以该使用者（USER）为主，并且工作目录也会改变。
    - 如果没有指定 USER ，内定是 root
  - 权限详解(链接)

- 公共目录
  - `/etc`
    - 最重要的根目录之一
    - 存储的系统文件
    - `passwd`和`shadow`文件所在位置
  - `/var`
    - var是数据变量的缩写
    - 存储系统上运行的服务或应用程序经常访问或写入的数据
      - 来自正在运行的服务和应用程序的日志文件被写入此处`/var/log`
  - `/root`
    - 是root用户的主目录
  - `/tmp`
    - 该目录是易失的，用于存储只需要访问一次或两次的数据。
    - 一旦计算机重新启动，此文件夹的内容就会被清除。
    - **在渗透测试中对我们有用的是，默认情况下任何用户都可以写入此文件夹。这意味着一旦我们可以访问一台机器，它就可以作为存储我们的枚举脚本之类的东西的好地方。**
### Linux基础 part.3
- 终端文本编辑器
  - vim(链接)
- 实用软件
  - `wget` 下载程序、脚本甚至图片等
    - `wget https://example.com/example.txt`
  - `scp` 使用SSH在两台终端间传输文件
    - `scp important.txt ubuntu@192.168.1.30:/home/ubuntu/transferred.txt`
    - `scp ubuntu@192.168.1.30:/home/ubuntu/documents.txt notes.txt` 
  - 轻量级Web服务
    - `python3 -m http.server`
- 进程101
  - `ps`
    - 查看其他用户的进程和系统进程，使用 `ps aux`
    - `top` 进程的实时统计信息
  - `kill` 终止进程
  - 进程如何开始
    - 系统启动时，`systemd`是最先启动的进程之一
    - 之后的所有进程都是`systemd`的子进程
  - `systemctl`
    - `systemctl [option] [service]`
      - `systemctl start apache2`
      - 常见`[option]`
        - `start` 启动
        - `stop` 停止
        - `enable` 开机启动
        - `disable` 关闭开机启动
        - `restart` 重启
        - `reload` 重新加载文件
        - `status` 状态
  - 前台和后台
    - `&` 命令在后台运行
    - `CTRL+Z` 将正在前台执行的命令放到后台，并且暂停
    - `jobs` 查看有多少在后台运行的命令
    - `fg %number` 将后台中的命令调至前台继续运行
    - `bg %number` 将一个在后台暂停的命令，变成继续执行
- 自动化（自启动）
  - 文件在 `/etc/crontab`
  - 使用 [Crontab生成器](https://crontab-generator.org/) 快速友好的生成
- 软件更新
  - `/etc/apt/sources.list` 
- 系统日志
  - `/var/log`

### Linux扩展
- [Bash脚本](https://github.com/MasterandRoot/Learn-THM/blob/main/Bash%20Scripting.md)
- [正则表达式]()

## Windows 基础
### Windows基础 part.1
- GUI
- 文件系统
  - NTFS
    - 在NTFS卷上，可设置文件或文件夹的权限
    - 备用数据流(ADS)
      - 从安全角度来看，恶意软件编写者使用 ADS 来隐藏数据
- system32文件夹

### Windows基础 part.2
- 系统配置 `msconfig`
  - 常规
    - 在“常规”选项卡中，可选择在启动时为 Windows 加载哪些设备和服务。
  - 引导
    - 在引导选项卡中，可为操作系统定义各种引导选项。 
  - 服务
    - 服务选项卡列出了为系统配置的所有服务，无论其状态如何（运行或停止）。服务是在后台运行的一种特殊类型的应用程序。  
  - 启动
    - 使用任务管理器 `taskmgr`管理启动项。
  - 工具
    - 系统实用工具列表
- 工具 —— 更改UAC设置
- 工具 —— 计算机管理
  - 系统工具
    - 任务计划程序
      - 可创建管理计算机将在指定时间自动执行的常见任务
    - 事件查看器
      - 查看系统日志
    - 共享文件夹
    - 性能
    - 设备管理器
  - 存储
    - 磁盘管理
  - 服务和应用程序
    - 服务
    - WMI控件
      - 已弃用,被 powershell 替代
- 工具 —— 系统信息
  - 硬件资源
    - 是可分配的可寻址总线路径，允许外围设备和系统处理器相互通信
  - 组件
    - 可以查看有关计算机上安装的硬件设备的特定信息。有些部分不显示任何信息，但有些部分会显示
  - 软件环境
    - 有关嵌入操作系统的软件和您已安装的软件的信息。此部分中还可以看到其他详细信息，例如环境变量和网络连接
- 工具 —— 资源监视器
- 工具 —— 命令提示符
  - `netstat` 显示协议统计信息和当前 TCP/IP 网络连接
    - `netstat /?` 帮助手册
  - `net` 管理网络资源
    - `net help commands` 帮助手册
- 工具 —— 注册表编辑器
### Windows基础 part.3
- Windows 更新(update)
  - 通常在每个月的第二个星期二
- Windows 安全
  - 病毒和威胁防护
    - 当前威胁
    - “病毒和威胁防护”设置
  - 防火墙与网络保护
  - 应用和浏览器控制
  - 设备安全
- 小结
  - [Living-Off-the-Land Binaries](https://lolbas-project.github.io/)







