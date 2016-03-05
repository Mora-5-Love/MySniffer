#MySniffer
arp双向欺骗以及http报文的嗅探（C语言）
1、分析arp，http报文结构，发送和接收arp报文
2、借助libpcap库和字典实现了http明文数据的嗅探。

系统结构
arptool：集成了arp包的封装，发送，接受，和活动主机的储存。
sniff：利用libpcap库设置过滤器截获http数据包。

使用说明
循环扫描网段内活动主机是根据攻击者主机的内网ip（eg：192.168.1.119）最后一位置0（192.168.1.0），然后扫描最后一位为1-254的主机（192.168.1.1-192.168.1.254）。
    ./arptool 
                -i  [interface]          //传入网卡名 （eg：eth0）
                -h [help]            //查看帮助
选择活动主机进行欺骗的时候会标示出可能的网关ip。然后欺骗的主机必须包含网关。

