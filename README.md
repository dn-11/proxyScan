# ProxyScan

Scan unauthenticated socks5 and exports them as proxy providers.

很多配网小子喜欢在路由器上配代理，同时把 WAN 方向的访问打开了，尤其是在高校网段。

因此编写了这样一个工具来警醒各位正确配置防火墙的重要性。

![output.png](./output.png)

# Start

```shell
go install github.com/hdu-dn11/proxyScan@latest
sudo proxyScan -prefix 0.0.0.0/0 -pcap
```

pcap mode requires root permission.

you can also run on windows but slower.

pcap 模式需要 root 权限。

windows上也能跑，就是慢点