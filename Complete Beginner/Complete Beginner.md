# 完全初学者
### Google Dorking
- 常用关键搜索术语
  - **site** 指定网站
  - **filetype** 指定文件类型
    - - `site:bbc.co.uk filetype:pdf`
  - **catch** 指定缓存
  - **intitle** 标题包含
    - `intital:index.of`

### [Linux 基础](https://github.com/MasterandRoot/Learn-THM/blob/main/Pre%20Security/Linux%E5%9F%BA%E7%A1%80.md)

### 网络黑客基础知识
##### [Burp Suite]()
##### OWASP Top 10 - 2021
1. 访问控制破坏
  - 访问控制破坏允许攻击者绕过授权，从而允许他们查看敏感数据或执行他们不应该执行的任务。
  - [辅助阅读](https://bugs.xdavidhu.me/google/2021/01/11/stealing-your-private-videos-one-frame-at-a-time/)
  - [不安全的直接对象引用](https://github.com/MasterandRoot/Learn-THM/blob/main/Jr%20Penetration%20Tester/Jr%20Penetration%20Tester.md#idor)
2. 加密失败( Cryptographic Failures)
  - 传输加密
    - 中间人攻击弱加密
  - 静态数据加密
    - 数据库失密(SQLite)
3. 注入
  - [命令注入](https://github.com/MasterandRoot/Learn-THM/blob/main/Jr%20Penetration%20Tester/Jr%20Penetration%20Tester.md#command-injection%E5%91%BD%E4%BB%A4%E6%B3%A8%E5%85%A5)
    - 又称远程代码执行
      - `uname -a`
      - `cat /proc/version`
  - [SQL注入](https://github.com/MasterandRoot/Learn-THM/blob/main/Jr%20Penetration%20Tester/Jr%20Penetration%20Tester.md#sql%E6%B3%A8%E5%85%A5)
4. 不安全设计(Insecure Design)
  - 不安全的密码重置
    - 不久前 Instagram上就出现了此类漏洞的一个很好的例子。Instagram 允许用户通过短信向他们的手机号码发送 6 位代码进行验证，从而重置忘记的密码。如果攻击者想要访问受害者的帐户，他可以尝试暴力破解 6 位代码。正如预期的那样，这不可能直接实现，因为 Instagram 实施了速率限制，因此在 250 次尝试后，用户将被阻止进一步尝试
    - 然而，攻击者发现速率限制仅适用于来自同一 IP 的代码尝试。如果攻击者有多个不同的 IP 地址来发送请求，他可以为每个 IP 尝试 250 个代码。对于 6 位代码，有一百万个可能的代码，因此攻击者需要 1000000/250 = 4000 个 IP 才能覆盖所有可能的代码。 这听起来似乎需要拥有大量的 IP，但云服务可以轻松地以相对较小的成本获取这些 IP，从而使这种攻击变得可行
      - 易猜测的密码重置问题
5. 安全配置错误(Security Misconfiguration)
  - 云服务（例如 S3 存储桶）的权限配置不当
  - 启用不必要的功能，例如服务、页面、帐户或权限
    -  例: Werkzeug 控制台开放调试接口
  - 密码未更改的默认帐户
  - 错误消息过于详细，允许攻击者找到有关系统的更多信息
  - 不使用 HTTP 安全标头
6. 易受攻击和过时的组件(Vulnerable and Outdated Components)
  - 漏洞利用
7. 身份验证失败
8. 软件和数据完整性故障(Software and Data Integrity Failures)
  - hash值
  - 软件完整性故障(Software Integrity Failures)
    - 现代浏览器允许您沿着库的 URL 指定哈希，以便仅当下载文件的哈希与预期值匹配时才执行库代码。这种安全机制称为子资源完整性 (SRI)
  
    ```javascript
    <script src="https://code.jquery.com/jquery-3.6.1.min.js" integrity="sha256-o88AwQnZB+VDvE9tvIXrMQaPlFFSUTR+nldQm1LuPXQ=" crossorigin="anonymous"></script>
    ```
    - 可以访问 https://www.srihash.org/ 为任何库生成哈希值
  - 数据完整性故障(Data Integrity Failures)
    - JWT 令牌
  
      ![JWT令牌](./image/jwt_01.png)

      - **Header** 包含指示这是 JWT 的元数据，并且使用的签名算法是 HS256
      - **Payload** 包含键值对以及 Web 应用程序希望客户端存储的数据
      - **Signature** 类似于哈希，用于验证有效负载的完整性
      - 如果更改 Payload，Web 应用程序可以验证签名是否与有效负载不匹配，并知道篡改了 JWT。与简单的哈希不同，此签名涉及仅使用服务器持有的密钥，这意味着如果更改有效负载，除非知道密钥，否则将无法生成匹配的签名
      - 令牌的 3 个部分中的每一个部分都是使用 Base64 编码的简单明文。可以使用工具对 Base64 进行编码/解码
    - JWT 令牌破解
      1. 修改令牌的标头部分，以便alg 标头包含 value none
      2. 删除签名部分
     
        ![JWT令牌破解](./image/jwt_02.png)
9. 安全日志记录和监控故障
10. [服务器端请求伪造（SSRF）](https://github.com/MasterandRoot/Learn-THM/blob/main/Jr%20Penetration%20Tester/Jr%20Penetration%20Tester.md#ssrf)

##### OWASP Juice Shop
  -  