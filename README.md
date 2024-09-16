# Overview

A basic low level Python script to capture and analyse network packets using raw sockets to capture ethernet frames. 

Each ethernet frame is broken down according to the ethernet frame structure, into the source and destination MAC addresses and Ether Type (data & checksum) and the IP packet.
<img width="703" alt="Screenshot 2024-09-16 at 12 50 01" src="https://github.com/user-attachments/assets/b098f245-9902-418e-aebb-31d75b4f887d">

If the ethernet protocol is IPv4, then the IPv4 header is broken down according to its structure, into the header length, protocol, IP addresses, payload and a few other bits.

<img width="608" alt="Screenshot 2024-09-16 at 12 50 29" src="https://github.com/user-attachments/assets/c8181cf2-02a4-4bfc-8d04-665ed2949ec2">

Then depending on which protocol the ipv4 packet is, ICMP, TCP or UDP, it is broken down accordingly.

TCP packet:

<img width="626" alt="Screenshot 2024-09-16 at 12 54 36" src="https://github.com/user-attachments/assets/da336ee3-be58-45f1-9aaa-38a97d82b72b">

As some behaviors of the socket module depend on the operating system socket API and there is no uniform API for using a raw socket under a different operating system, we need to use a Linux OS to run this script. So, if you are using Windows or macOS, please make sure to run this script inside a virtual Linux environment. Also, most operating systems require root access to use raw socket APIs.
