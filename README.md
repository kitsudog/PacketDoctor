PacketDoctor
============
一个利用Pcap实现的包分析工具
```
usage:
包监听工具
 -c,--conf <arg>      指定配置文件
 -C,--command <arg>   不使用jnetpcap来获取数据 文件名变量为{}
 -d,--debug           只显示调试信息
 -f,--file <arg>      指定文件
 -g,--gui             使用图形化界面
 -H,--handler <arg>   指定策略
 -h,--host <arg>      指定服务器ip或域名(仅截获与此主机的沟通)
    --help            显示帮助
 -i,--if <arg>        指定接口
 -L,--loop            指定为lo 为接口
 -l,--list            显示所有的网卡列表
 -n,--num <arg>       包的数量(默认1,000,000)
 -p,--port <arg>      指定端口(仅截获与此端口的沟通)
 -s,--skip <arg>      指定跳过的帧数(与file接口配合有意义)
 -S,--source <arg>    指定本机ip
 -w,--write <arg>     导出到文件
```

TODO
============
* 缺配置文件
* 子进程监控
* 写文件
* 缺发送长连接数据包(缺可行性分析)
* 缺发送短链接数据包(HTTP)
