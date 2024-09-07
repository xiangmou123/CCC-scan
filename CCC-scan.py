#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import argparse
import pandas as pd
from fake_useragent import UserAgent
from netaddr import IPNetwork
import asyncio
from bs4 import BeautifulSoup
import hrequests
import warnings

warnings.filterwarnings('ignore')

# 基础信息配置
class Config:
    ua = UserAgent()
    Ports_web = [80, 88, 443, 7001, 8000, 8008, 8888, 8080, 8088, 8089, 8161, 9090]
    Ports_other = [21, 22, 445, 1100, 1433, 1434, 1521, 3306, 3389, 6379, 8009, 9200, 11211, 27017, 50070]
    COUNT = 0
    TIMEOUT_HTTP = 2
    TIMEOUT_SOCK = 5
    PATH = ""
    OUTPUTDICT = {
        "ip": [],
        "域名": [],
        "端口": [],
        "状态码": [],
        "标题": [],
        "指纹": [],
        "响应长度": [],
        '是否有关键字': []
    }
    user_agent = ua.random
    colors = {
        'purple': '\033[95m',
        'blue': '\033[94m',
        'yellow': '\033[93m',
        'cyan': '\033[96m',
        'red': '\033[31m',
        'green': '\033[92m',
        'magenta': '\033[35m',
        'end': '\033[0m'
    }

# 美化输出
def setTag(info, color):
    if color == "red":
        return Config.colors['end'] + "|" + Config.colors['red'] + info
    elif color == "green":
        return Config.colors['end'] + "|" + Config.colors['green'] + info + Config.colors['end']
    elif color == "yellow":
        return Config.colors['end'] + "|" + Config.colors['yellow'] + info
    elif color == "blue":
        return Config.colors['end'] + "|" + Config.colors['blue'] + info
    elif color == "purple":
        return Config.colors['end'] + "|" + Config.colors['purple']  + info
    elif color == "cyan":
        return Config.colors['end'] + "|" + Config.colors['cyan'] + info + "   "+ Config.colors['end']
    elif color == "magenta":
        return Config.colors['end'] + "|" + Config.colors['magenta'] + info
    elif color == "end":
        return Config.colors['end'] + "|" + Config.colors['end'] + info

# 获取指纹信息
def getFinger(target, key):
    # 设置API的URL
    try:
        url = "https://www.themedetect.com/API/Tech"

        # 设置请求参数
        params = {
            'key': key,
            'url': target
        }
        # 发送GET请求
        response = hrequests.get(url, params=params)
        # 检查请求是否成功
        if response.status_code == 200:
            # 输出响应内容
            data = response.json()["results"]
            f = []
            for i in data:
                content=i["name"] + i["version"]
                f.append(content)
            if f:
                return ",".join(f)
            else:
                return None
    except:
        return None

# 图标
def setBanner():
    print(setTag("""
==================================================================
=    ___   ___   ___                                             =
=   / __\ / __\ / __\     ___  ___ __ _ _ __                     =
=  / /   / /   / /  _____/ __|/ __/ _` | '_ \                    =
= / /___/ /___/ /__|_____\__ \ (_| (_| | | | |                   =
= \____/\____/\____/     |___/\___\__,_|_| |_|                   =
=                                                                =
==================================================================
""", "cyan"))

# 用于反查域名
def getDomain(ip,port,keyword,key):
    try:
        rep = hrequests.get(url=f"http://api.webscan.cc/?action=query&ip={ip}", headers={
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.71 Safari/537.36"
            }, timeout=3)
        if rep.text != "null":
            results = rep.json()
            for result in results:
                domainName = result["domain"]
                title = result["title"]
                finger=getFinger(domainName,key)
                get_info(domainName, port,keyword,title, finger,ip)
        else:
            get_info(None, port, keyword, None, None, ip)
    except:
        pass

# 保存结果为csv
def save(save_file):
    """
    将内容追加到指定的文件中。
    参数：
    save_file: 保存文件的路径，可以是字符串或路径对象。
    content: 需要保存的内容，作为字符串传入。
    """
    try:
        result = pd.DataFrame(Config.OUTPUTDICT)
        result.to_csv(save_file, index=False, encoding="utf-8")
    except Exception as e:
        # 捕获文件I/O相关的错误，并打印错误信息
        print("文件写入失败")

# 清除脏数据
def clearTag(content):
    return content.replace(Config.colors['purple'], "").replace(Config.colors['cyan'], "").replace(
        Config.colors['magenta'], "").replace(Config.colors['blue'], "").replace(Config.colors['yellow'], "").replace(
        Config.colors['green'], "").replace(Config.colors['red'], "").replace(
        Config.colors['end'], "").replace(" ", "").replace("|","")

# 获取详细信息
def get_info(domain, port,keyword,title,finger,ip):
    """
    从指定URL获取信息，包括HTTP状态码、页面标题、服务器信息、Jenkins信息、Shiro信息等。

    参数：
    url: 目标URL。
    keyword: 可选的关键词，用于在页面内容中进行匹配。

    返回值：
    返回拼接的结果字符串，包含页面信息和关键词匹配结果。
    """
    # 检测web端口并获取信息
    protocol = "http" if port not in [443, 8443] else "https"

    try:

        if domain:
            url = f"{protocol}://{domain}:{port}{Config.PATH}"
        else:
            url = f"{protocol}://{ip}:{port}{Config.PATH}"

        response = hrequests.get(url, headers={'User-Agent': Config.user_agent}, timeout=Config.TIMEOUT_HTTP,
                                     verify=False,
                                     allow_redirects=True)
        soup = BeautifulSoup(response.content, "lxml")
        if response.status_code == 200:
            # 获取HTTP状态码
            info_code = setTag(str(response.status_code), "green")
        else:
            info_code = setTag(str(response.status_code), "red")

        if title:
            info_title = setTag(title, 'purple')
        else:
            info_title = setTag(soup.title.string, 'purple')
        # 获取响应内容长度
        info_len = setTag(str(len(response.content)), 'magenta')

        # 初始化服务器和Shiro信息

        info_shiro = ""
        # 检查响应头中的Jenkins信息
        info_jenkins = setTag(f" [jenkins {response.headers['X-Jenkins']}]" if 'X-Jenkins' in response.headers else "",
                           "yellow")
        infoFinger=""
        if finger==None:
            # 检查响应头中的服务器信息和X-Powered-By信息
            if 'Server' in response.headers:
                server_info = response.headers['Server']
                if 'X-Powered-By' in response.headers:
                    server_info += f" {response.headers['X-Powered-By']}"
                infoFinger = f" {setTag(server_info, 'yellow')}"
        else:
            infoFinger=setTag(finger, 'yellow')

        # 检查响应头中的Shiro信息
        if 'Set-Cookie' in response.headers and 'rememberMe=deleteMe' in response.headers['Set-Cookie']:
            info_shiro = "[Shiro]"
        domain_info=setTag(domain,"cyan")

        if ip:
            Config.OUTPUTDICT["ip"].append(ip)
        else:
            Config.OUTPUTDICT["ip"].append('')
        if domain:
            Config.OUTPUTDICT["域名"].append(domain)
        else:
            Config.OUTPUTDICT["域名"].append('')

        if port:
            Config.OUTPUTDICT["端口"].append(port)
        else:
            Config.OUTPUTDICT["端口"].append('')
        if info_code:
            Config.OUTPUTDICT["状态码"].append(clearTag(info_code))
        else:
            Config.OUTPUTDICT["状态码"].append('')
        if info_title:
            Config.OUTPUTDICT["标题"].append(clearTag(info_title))
        else:
            Config.OUTPUTDICT["标题"].append('')
        if infoFinger:
            Config.OUTPUTDICT["指纹"].append(clearTag(infoFinger))
        else:
            Config.OUTPUTDICT["指纹"].append('')
        if info_len:
            Config.OUTPUTDICT["响应长度"].append(clearTag(info_len))
        else:
            Config.OUTPUTDICT["响应长度"].append('')

        if keyword:
            if keyword in str(soup.text):
                k = setTag(f"有关键字{keyword}!!!", 'green')
                Config.OUTPUTDICT["是否有关键字"].append(clearTag(k))
            else:
                k = setTag(f"没有关键字{keyword}!!!", 'green')
                Config.OUTPUTDICT["是否有关键字"].append(k)
        else:
            k = setTag(f"没有关键字{keyword}!!!", 'green')
            Config.OUTPUTDICT["是否有关键字"].append(clearTag(k))
        # 拼接最终的结果字符串
        printConsole = setTag(ip,"cyan") + domain_info + setTag(str(port),"cyan") + info_code + info_title.replace(" ","").replace("\n","") + infoFinger + info_jenkins + info_shiro + info_len+setTag(k,"yellow")
        print(printConsole)
        return printConsole + k

    except:
        # 捕获所有requests库可能抛出的异常，并返回默认信息
        return setTag("open", "green")

# 端口扫描代码
async def connect(host, sem, keyword,key):
    async with sem:
        for port in Ports:
                # 尝试连接指定端口
            fut = asyncio.open_connection(host=host, port=port)
            try:
                reader, writer = await asyncio.wait_for(fut, timeout=Config.TIMEOUT_SOCK)
                if writer:
                    # 检测非web端口
                    if port in Config.Ports_other:
                        print(host+port+setTag("open", "green"))
                    else:
                        getDomain(host, port,keyword,key)
            except:
                # 处理连接超时或连接错误，不输出错误信息
                pass

# C段扫描代码
async def scan(mode, x, t, keyword,key):
    try:
        # 加入信号量用于限制并发数
        sem = asyncio.Semaphore(t)
        tasks = []
        # IP模式：10.1.1.1/24
        if mode == 'ips':
            try:
                ips = [str(ip) for ip in IPNetwork(x)]
            except Exception:
                print("[x] 请指定ip段")
                exit(1)
            for host in ips:
                tasks.append(asyncio.create_task(connect(host, sem, keyword,key)))
        # 文件模式：文件格式支持ip、域名
        if mode == 'file':
            with open(x, 'r') as f:
                for line in f.readlines():

                    line = line.rstrip()

                    if len(line) != 0:
                        host = line if '://' not in line else line.split('//')[1]
                        tasks.append(asyncio.create_task(connect(host, sem, keyword,key)))
        await asyncio.wait(tasks)
        print("======================================任务完成！！！======================================")
    except Exception as e:
        print(e)
        print("任务已取消")

# 主程序入口
def main():
    global Ports, PATH
    setBanner()
    # 初始化命令行参数解析器
    parser = argparse.ArgumentParser(
        usage='\nCCC-scan.py -i 182.92.178.175/24 -o test.csv -web -t 50\nCCC-scan -f url.txt -t 100\nCCC-scan -i 192.168.0.1/24 -t 100 -q -port 80,8080 -path /actuator',
        description="CCC-scan",
    )

    # 基础参数组
    basic = parser.add_argument_group('基础参数')
    basic.add_argument("-i", dest="ips", help="使用IP段 (例如 192.168.0.1/24)")
    basic.add_argument("-f", dest="file", help="使用IP或域名文件")
    basic.add_argument("-t", dest="threads", type=int, default=256, help="设置线程数 (默认 50)")
    basic.add_argument("-o", dest="output", default="output.csv", help="保存文件路径")

    # 高级参数组
    god = parser.add_argument_group('高级参数')
    god.add_argument("-port", dest="port", help="指定端口 (例如 '1,2,3,4' 或者 1~65536)")
    god.add_argument("-path", dest="path", help="请求路径 (例如 '/1.jsp')")
    god.add_argument("-keyword", dest="keyword", help="指定关键字匹配web里的内容")
    god.add_argument("-key", dest="key", default='',help="whatcms.org网站的key")
    god.add_argument("-web", dest="web", action="store_true", help="仅扫描Web端口")


    args = parser.parse_args()

    # 根据-web参数设置要扫描的端口
    Ports = Config.Ports_web if args.web else Config.Ports_web + Config.Ports_other

    # 如果指定了端口，则覆盖默认端口设置
    if args.port:
        if "~" in args.port:
            p=args.port.split('~')
            Ports=[i for i in range(int(p[0]),int(p[1])+1)]
        else:
            Ports = args.port.split(',')
    # 如果没有提供IP段或文件，提示使用帮助
    if not args.ips and not args.file:
        print(Config.colors["red"] + "[x] 请使用 'SSS-scan -h' 查看帮助信息" + Config.colors["end"])
        sys.exit(0)
    # 设置请求路径
    if args.path:
        PATH = args.path
    # 扫描IP段
    if args.ips:
        print(Config.colors["yellow"] + '目标: ' + Config.colors["blue"] + args.ips + Config.colors["purple"] + ' | ' +
              Config.colors["yellow"] + '线程数: ' + Config.colors["blue"] + str(args.threads) + Config.colors["end"] +
              Config.colors["yellow"] + Config.colors["purple"] + ' | ' + '端口: ' + Config.colors["blue"] + str(
            Ports) + Config.colors["end"] + '\n')
        try:
            asyncio.run(scan('ips', args.ips, args.threads, args.keyword,args.key))
        except KeyboardInterrupt:
            print(Config.colors["red"] + "\n检测到CTRL+C，正在退出..." + Config.colors["end"])
            sys.exit(0)

    # 扫描文件中的IP或域名
    if args.file:
        print(
            Config.colors["yellow"] + '目标: ' + Config.colors["blue"] + args.file + Config.colors["purple"] + ' | ' +
            Config.colors["yellow"] + '线程数: ' + Config.colors["blue"] + str(args.threads) + Config.colors["end"])
        print(Config.colors["yellow"] + '端口: ' + Config.colors["blue"] + str(Ports) + Config.colors["end"] + '\n')
        try:
            asyncio.run(scan('file', args.file, args.threads, args.keyword,args.key))
        except KeyboardInterrupt:
            print(Config.colors["red"] + "\n检测到CTRL+C，正在退出..." + Config.colors["end"])
            sys.exit(0)
    if args.output:
        save(args.output)


if __name__ == '__main__':
    main()
