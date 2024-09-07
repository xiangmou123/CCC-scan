# CCC-scan

## 项目介绍

本项目借鉴于https://github.com/j3ers3/Cscan/tree/master,大学生练手项目

用于扫描C段下的所有端口，以及ip上面所有的历史域名、指纹、标题、关键字等信息

![](https://github.com/xiangmou123/CCC-scan/blob/main/picture/1.png)

![](https://github.com/xiangmou123/CCC-scan/blob/main/picture/2.png)

## 改进之处



1、原本的user-agent过于固定，为了防止user-agent检测，采用fake_useragent 库轮换 User-Agent

2、细化了各参数的详情，并将各类输出详情翻译成中文

3、增加了ip反查域名

4、更改了指纹识别方式

5、增加了输出选项可以输出成csv格式

## 备注

目前速度太慢了，晚点会改进，项目有什么问题或者建议可以私信留言。