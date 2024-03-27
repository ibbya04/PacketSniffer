import socket
import struct
import sys


def main():
    # # creates a raw socket capable of capturing TCP packets at IP level.
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.ntohs(3))

    # infinite loop to recieve data from socket, then formats and prints data
    while True:
        raw_data, addr = s.recvfrom(65535)
        dest_mac, src_mac, proto, data = ethernet_head(raw_data)
        print('Ethernet Frame:')
        print('Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, proto))

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
def ipv4_packet:
    version_header = data[0]
    # bit shift right to remove header length(last 4 bytes)
    version = version_header >> 4
    header_length = (version_header * 15) * 4
    # extracts binary from payload/IP
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', [:20])
    return version, header_length, ttl, proto, get_ipv4(src), get_ipv4(target), data[header_length:]

# formats IPv4 address e.g. 168.0.0.1
def get_ipv4(address):
    ipv4_address = '.'.join(map(str, address))
    return ipv4_address



main()
    