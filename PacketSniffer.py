#=========================================================================
# Goal of this code is to:
#      1. Understand how raw packets work as ethernet frames
#      2. Split the packet into sections excluding the front and end buffers
#      3. Parse and format the sections into readable information
#      4. Identify and unpack differently based on protocols
# Note this will only sniff and parse incoming TCP packets ON LINUX
#=========================================================================

import socket, struct

# unpacks the ethernet frame
# takes in unparsed ethernet frame
# returns the formated MAC addr of the dest and src, the protocol type, and data inside the frame
# to be run before determining protocol and calling appropriate function
def ethernet_frame(data):
    # note that a ethernet package is made up of 6 bytes for dest, 6 bytes for source, 2 bytes for protocol (eg IPv4)
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data)
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

# formats the bytes_addr passed into readable addresses
# takes in parsed MAC addresses from ethernet_frame function
# returns the mac address w/ formatting (eg AA:BB:CC:DD:EE:FF)
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

# formats the IPv4 ip address
# takes in parsed, unformatted address
# returns properly formatted ip address
def ipv4_format(ip_addr):
    return '.'.join(map(str, ip_addr))

# reads the data if the packet is has IPv4 protocol
# takes in the data passed from ethernet_frame
# NOTE IPv4 is made up of additional parts (version, ihl, type of service, total length, id, ttl, flags, header)
# including src and dest header, making a total of 20 additional bits
# NOTE src and dest will be in the form of an IP address
def ipv4_header(data):
    version_length = data[0]
    # bit shift to the right 4 bits to get version number
    version = version_length >> 4
    # use bitwise and to determine the start of data / end of header
    header_len = (version_length & 15) * 4
    ttl, proto, src, dest = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_len, ttl, proto, ipv4_header(src), ipv4_format(dest), data[header_len:]

# reads the TCP protocol segment of the packet
# takes in parsed data passed from ethernet_frame
# returns src, dest, sequence number, acknowledgement, offset, flags, and data in packet
def tcp_seg(data):
    src, dest, seq_num, ack, offset_flags = struct.unpack('! H H L L H', data[:14])
    # push bits to get just the offset
    offset = (offset_flags >> 12) * 4
    # separate and get each flag bit
    flag_urg = (offset_flags & 32) >> 5
    flag_ack = (offset_flags & 16) >> 4
    flag_psh = (offset_flags & 8) >> 3
    flag_rst = (offset_flags & 4) >> 2
    flag_syn = (offset_flags & 2) >> 1
    flag_fin = offset_flags & 1
    return src, dest, seq_num, ack, offset, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

# reads and formats the UDP segment of the packet
# takes in parsed data passed from ethernet_frame
# returns src, dest, length, and data
def udp_seg(data):
    src, dest, len = struct.unpack('! H H 2x H', data[:8])
    return src, dest, len, data[8:]

# reads and parses the ICMP header of the segment
# takes in parsed data passed from the ethernet frame
def icmp_seg(data):
    type, code, checksum = struct.unpack('! B B H', data[:4])
    return type, code, checksum, data[4:]

# main code that will set up a loop that will continually monitor the socket
def mainLinux():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, addr = s.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print('Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))

#mainLinux()