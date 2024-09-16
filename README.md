# PacketSniffer

As some behaviors of the socket module depend on the operating system socket API and there is no
uniform API for using a raw socket under a different operating system, we need to use a Linux OS to
run this script. So, if you are using Windows or macOS, please make sure to run this script inside a
virtual Linux environment. Also, most operating systems require root access to use raw socket APIs.
