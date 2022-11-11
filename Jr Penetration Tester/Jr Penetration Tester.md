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
  - 使用





