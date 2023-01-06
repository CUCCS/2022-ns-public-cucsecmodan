# Chap0x03

---

## 实验要求

* 安装 tinyproxy
* 编辑 tinyproxy 配置
* /etc/init.d/tinyproxy start
* 设置虚拟机联网方式为 NAT 和端口转发，默认 tinyproxy 监听 8888 端口
* 主机浏览器设置代理指向 tinyproxy 的服务地址
* 虚拟机里开启 wireshark 抓包
* 主机访问 https 站点
* 结束抓包，分析抓包结果

---

## 实验流程

安装 tinyproxy

```bash
sudo apt update
sudo apt install tinyproxy
```

配置 tinyproxy，取消 Allow 192.16.0.0/16 注释

```bash
sudo vi /etc/tinyproxy/tinyproxy.conf
```

![](imgs/allow.png)

配置虚拟机 hostonly 和 NAT 网络

![](./imgs/nat.png)

配置宿主机浏览器代理设置（switchyomega）

![](./imgs/browser.png)

在虚拟机中开启 wireshark 抓包，选择 hostonly 网卡
同时宿主机访问百度，可以在虚拟机中的 wireshark 里面看到转发的流量包

![](./imgs/baidu.png)

通过 `http.request.method eq CONNECT` 可以查看 HTTPS 代理请求

![](./imgs/connect.png)

通过 `http.request.method eq GET` 可以查看 HTTP GET 代理请求

![](./imgs/get.png)

---

## 参考资料

[老师课件](https://c4pr1c3.github.io/cuc-ns/chap0x03/exp.html)