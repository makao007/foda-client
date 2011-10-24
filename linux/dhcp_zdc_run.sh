#!/bin/bash

#检测root权限
if [ `id -u` -ne 0 ]
then
    echo "Need to be ROOT."
    exit 1
fi

#开始认证，DHCP模式，后台运行
./zdclient -u username -p password -b --dhcp

#如果认证成功，执行dhclient更新系统ip
if [ $? -eq 0 ]
then
	dhclient
fi

exit 0
