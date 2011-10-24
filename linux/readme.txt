ZDC_Client v0.4 Readme

编译：
	编译需要libpcap库，一般Linux发行版里面安装libpcap-dev包即可，如ubuntu： sudo apt-get install libpcap-dev
	然后从命令行进入源代码目录，运行make，应该很快就能生成ZDC_Client，当然前提是系统中安装了gcc等编译环境，这里不再累赘。
	理论上兼容包括Mac、Solaris等Unix系系统。
	
运行：
	运行需要root权限，看例子即可：
	
	sudo ./zdclient -u username -p password --background
	
	u、p、分别是用户名、密码，--background参数可让程序进入后台运行，具体可./zdclient --help查看
	
	压缩包内提供了两个启动脚本st_zdc_run.sh和dhcp_zdc_run.sh，分别包含了用于静态IP和动态IP环境的推荐参数，区别请看DHCP模式一节；
	用gedit等编辑软件修改sh文件内的username、password，以后运行sudo ./xx_zdc_run.sh即可。
	
终止：
	默认方式启动的程序，按Ctrl + C即可正常下线，程序终止；
	在以后台方式启动后，程序每隔约20秒就输出一次协议提示，其中方括号［xxx］的数值为进程pid，可用sudo kill xxx可终止进程。
	如果已经了运行时的关闭窗口，就只能使用ps -A|grep zdclient来找到pid了。

DHCP模式：
	这里提到的DHCP模式不是完全指网卡是否用DHCP获取IP，DHCP模式的特点是：
	1.在Windows启动后，提示本地连接受限，网卡IP为169.254.x.x的格式，使用客户端认证后才重新获取IP；
	2.在Linux下启动后，网卡IP为空；
	如果符合以上两点，则必须使用--dhcp模式启动zdclient，而且在认证成功后，是需要运行系统的DHCP客户端重新获取一次IP的，通常是dhclient，这一点在启动脚本dhcp_zdc_run.sh内已经包含。
	
	至于在认证前已经能获得IP的环境，不是这里所说的动态模式，使用静态模式启动即可。

版本号：
	认证报文中包含了协议版本号，zdclient 0.4版中的默认版本号是以武汉大学官方客户端的3.5.04.1013fk为准，已知更新的版本是3.5.04.1110fk，不过暂时不影响使用。如果您使用时发现提示&&Info: Invalid Username or Client info mismatch.，很可能是软件的版本号和您使用环境的认证系统不匹配，可尝试使用--ver参数自定义版本号，或联系作者PT，帮助ZDClient兼容您的环境。
	
	

A PT Work. 

Blog: http://apt-blog.co.cc
GMail: pentie@gmail.com

2009-05-20 于广州大学城
