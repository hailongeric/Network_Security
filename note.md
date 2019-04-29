### webview
JSbridge  官方.addjavascripInternetface()
elege
BROWSABLE

# 网络安全

### Internet Infrastructure
#### AS内部 RIP(路由信息协议)和OSFP(开放最短路径优先路由)
###### IP安全
* 认证
* 保密
* 密钥管理
> 互联网体系结构委员会（IAB）

ＥＳＰ　封装安全载荷
ＡＨ　认证报头

* 传输模式
  * 增强了对ＩＰ包载荷的保护。

> IPSec的安全策略

* 安全互联

    * 安全关联数据库（SAD）
    * 安全策略数据库（SPD）

    * 三大参数
        * 安全参数索引（SPI）
        * IP目的地址
        * 安全协议标识

计算机安全的目标：保密性、完整性、可用性、可认证性、可审计两种攻击模式：

主动攻击：修改数据量或创造错误流  1.（冒充）masquerade   2.重放    3. 修改信息   4. Dos 

被动攻击：1. 消息泄露   2.流量分析

加密系统的四个要素: 密文  明文  算法   密钥

Kerckhoff的原则：密码的安全性决不能依赖于任何不易改变的东西

三个安全法则：

 * 绝对安全的系统不存在
 * 为了降低脆弱性，需要更多的支出
 * 密码系统是典型的旁路攻击，不能渗透攻击

密码的基本原理：

* 如果有许多聪明的人都没有破解密码，那么是安全的

常规密码的技术：1.置换（permute）  2.替换

凯撒密码可以通过字母的频率分析很容易攻击

“Rail-Fence“栅栏密码、一次一密

对称密码体制（也称密钥密码）：

* 块加密    密钥依赖于S-boxes或轮密码   DES典型的块密码
* 流加密    有关假随机流密钥生成器，不能使用相同的密码流
  * key是生成密钥的种子（PRNG伪随机发生器pseudo random number generator）
  * 种子应该足够大，避免穷举
  * PRNG:长期无重复     统计随机    没有相关性
  * RC4 典型的流密码    密钥8-bits的值    置换

快密码的模式：CBC(Cipher Block Chaining)、CFB(Cipher Feedback Model) 、OFB(Output FeedBack Model)

KDC（密钥分发中心)

#### 公钥加密的动机

RSA攻击：猜测明文的攻击，试信息

选择明文攻击：让其给信息签名，即解密

m^e<n马上可以试出来

MITM攻击

Kerberos

