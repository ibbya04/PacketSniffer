import socket
import struct
import sys



def main():
    # # creates a raw socket capable of capturing TCP packets at IP level.
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    # infinite loop to recieve data from socket, then formats and prints data
    while True:
        raw_data, addr = s.recvfrom(65535)
        dest_mac, src_mac, eth_proto, data = ethernet_head(raw_data)
        print('Ethernet Frame:')
        print('     Destination MAC Address: {}, Source MAC Address: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))

        # check if ethernet protocol is 8
        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, ipv4_payload) = ipv4_packet(data)
            print('     IPv4 Packet:')
            print('         Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
            print('         Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

            if proto == 1:
                icmp_type, code, checksum, ipv4_payload = unpack_icmp_packet(ipv4_payload)
                print('     ICMP Packet:')
                print('         Type: {}, Code: {}, Checksum: {},'.format(icmp_type, code, checksum))
                print('         Data: {}'.format(ipv4_payload))

            elif proto == 6:
                (src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, ipv4_payload) = unpack_tcp_segment(ipv4_payload)
                print('     TCP Segment:')
                print('         Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                print('         Sequence: {}, Acknowledgement: {}'.format(sequence, acknowledgement))
                print('         Flags:')
                print('         URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                print('         Data:'.format(ipv4_payload))

            elif proto == 17:
                 src_port, dest_port, size, ipv4_payload = unpack_udp_segment(ipv4_payload)
                 print('        UDP Segment:')
                 print('         Source Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, size))
                 print('         Data: {}'.format(ipv4_payload))




def ethernet_head(raw_data):
    # unpacks binary data. ! specifies big endian as network data is big endian.
    # dest and source mac addresses are 6 bytes each, hence 6s. H specifies unsinged int, 2 bytes for source.
    dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])

    # get_mac_addr function converys MAC addresses into human readable format
    dest_mac = get_mac_addr(dest)
    src_mac = get_mac_addr(src)

    # converts to big endian
    proto = socket.htons(prototype)
    # payload
    data = raw_data[14:]
    return dest_mac, src_mac, proto, data

# converts bytes into formatted MAC address e.g. 40:00:40:AB:C0:D0
def get_mac_addr(bytes):
    # formats each byte without need for a loop
    bytes_str = map('{:02x}'.format, bytes)
    # joins bytes together wiht ':' inbetween and converts all to uppercase
    mac_address = ':'.join(bytes_str).upper()
    return mac_address

# unpacks IPv4 packet which lies within ethernet frame payload.
def ipv4_packet(data):
    version_header = data[0]
    # bit shift right to remove header length(last 4 bytes)
    version = version_header >> 4
    header_length = (version_header & 15) * 4
    # extracts binary from payload/IP
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    #format IP addresses
    src_ip = get_ipv4(src)
    target_ip = get_ipv4(target)
    #extracts payload
    ipv4_payload = data[header_length:]
    return version, header_length, ttl, proto, src_ip, target_ip, ipv4_payload

# formats IPv4 address e.g. 168.0.0.1
def get_ipv4(address):
    ipv4_address = '.'.join(map(str, address))
    return ipv4_address

# unpacks ICMP packet if protocol = 1
def unpack_icmp_packet(data):
    # unpack binary data according to ICMP packet diagram, 1st byte = icmp type
    # 2nd byte = code, 3rd+4th byte = checksum 
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# unpacks TCP segment if protocol = 6
def unpack_tcp_segment(data):
    # unpacks binary data, first 4 bytes source & destination ports, ...
    (src_port, dest_port, sequence, acknowledgement, offset_res_flags) = struct.unpack('! H H L L H', data[:14])
    # unpacked 2 bytes which contain offset, reserved and flags together
    # need to be split into 4 bits for offset, 4 bits for reserved, and 8 bits/1 byte for flags using bitwise ops.
    offset = (offset_res_flags >> 12) * 4
    flag_urg = (offset_res_flags & 32) >> 5
    flag_ack = (offset_res_flags & 16) >> 4
    flag_psh = (offset_res_flags & 8) >> 3
    flag_rst = (offset_res_flags & 2) >> 2
    flag_syn = (offset_res_flags & 2) >> 1
    flag_fin = offset_res_flags & 1
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

# unpacks UDP segment if protocol = 17
def unpack_udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

main()
    