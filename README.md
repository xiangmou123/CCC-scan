# C-Sscan

## 项目介绍

本项目借鉴于https://github.com/sma11new/ip2domain和https://github.com/j3ers3/Cscan/tree/master



## 改进之处

1、原本的协程只有在端口多的情况下速度才会有所体现，一旦要搜索的端口过少，就会变得很慢，因此加入了多线程来解决这一问题

2、原本的user-agent过于固定，为了防止user-agent检测，采用fake_useragent 库轮换 User-Agent

3、将代码变的更简洁

4、个人认为没有必要设置安静模式，删除了安静模式

5、细化了各参数的详情，并将各类输出详情翻译成中文

6、通过使用 `requests.adapters.HTTPAdapter` 或者 `aiohttp.TCPConnector` 配置连接池，减少每次请求的连接时间。

7、增加了清理缓存机制，避免在请求频率高的情况下重复请求相同的内容。