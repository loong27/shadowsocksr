ShadowsocksR
===========

[![Build Status]][Travis CI]

一个快速隧道代理，帮助你穿越防火墙。

> 本仓库已全面兼容 Python 3（同时保留对 Python 2 的回退支持）。

服务端
------

### 安装

Debian / Ubuntu:

    apt-get install git
    git clone git@github.com:loong27/shadowsocksr.git

CentOS:

    yum install git
    git clone git@github.com:loong27/shadowsocksr.git

Windows:

    git clone git@github.com:loong27/shadowsocksr.git

### Linux 单用户使用方式

如果克隆到 `~/shadowsocksr` 目录：
进入 `~/shadowsocksr`，运行：

    bash initcfg.sh

进入 `~/shadowsocksr/shadowsocks`，运行：

    python server.py -p 443 -k password -m aes-128-cfb -O auth_aes128_md5 -o tls1.2_ticket_auth_compatible

通过 `-h` 查看所有选项。

推荐使用配置文件：回到 `~/shadowsocksr` 编辑 `user-config.json`，再进入 `~/shadowsocksr/shadowsocks`，运行：

    python server.py

后台运行：

    ./logrun.sh

停止服务：

    ./stop.sh

查看日志：

    ./tail.sh


客户端
------

* [Windows] / [macOS]
* [Android] / [iOS]
* [OpenWRT]

在本地 PC 或手机上使用图形化客户端。详细使用方式请查阅对应客户端的 README。

文档
----

所有文档均可在 [Wiki] 中查阅。

许可证
------

Copyright 2015 clowwindy

Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.

Bug 与问题反馈
--------------

* [Issue Tracker]



[Android]:           https://github.com/shadowsocksr/shadowsocksr-android
[Build Status]:      https://travis-ci.org/shadowsocksr/shadowsocksr.svg?branch=manyuser
[Debian sid]:        https://packages.debian.org/unstable/python/shadowsocks
[iOS]:               https://github.com/shadowsocks/shadowsocks-iOS/wiki/Help
[Issue Tracker]:     https://github.com/loong27/shadowsocksr/issues?state=open
[OpenWRT]:           https://github.com/shadowsocks/openwrt-shadowsocks
[macOS]:             https://github.com/shadowsocksr/ShadowsocksX-NG
[Travis CI]:         https://travis-ci.org/shadowsocksr/shadowsocksr
[Windows]:           https://github.com/shadowsocksr/shadowsocksr-csharp
[Wiki]:              https://github.com/breakwa11/shadowsocks-rss/wiki
