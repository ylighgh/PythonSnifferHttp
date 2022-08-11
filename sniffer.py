#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import socket
from struct import *


def get_mac_addr(mac_raw):
    byte_str = map('{:02x}'.format, mac_raw)
    mac_addr = ':'.join(byte_str).upper()
    return mac_addr


class Frame:
    def __init__(self, row_data) -> None:
        dest, src, prototype = unpack('!6s6sH', row_data[:14])
        self.dest_mac = get_mac_addr(dest)
        self.src_mac = get_mac_addr(src)
        self.protocol = socket.htons(prototype)
        self.data = row_data[14:]


class Packet:
    def __init__(self, row_data) -> None:
        version_header_length = row_data[0]
        self.version = version_header_length >> 4
        self.header_length = (version_header_length & 15) * 4
        self.ttl, self.protocol, self.src, self.dest = unpack('!8xBB2x4s4s', row_data[:20])
        self.data = row_data[self.header_length:]


class Segment:
    def __init__(self, row_data) -> None:
        self.src_port, self.dest_port, self.seq, \
        self.ack, self.offset_reverse_flags = unpack('!HHLLH', row_data[:14])
        self.offset = (self.offset_reverse_flags >> 12) * 4
        self.data = row_data[self.offset:]


def main():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        row_data, addr = s.recvfrom(65535)
        frame = Frame(row_data)

        # IPv4
        if frame.protocol == 8:
            packet = Packet(frame.data)

            # TCP = 6
            if packet.protocol == 6:
                segment = Segment(packet.data)

                if (segment.src_port == 8081 or segment.dest_port == 8081) and len(segment.data) > 0:
                    print("--------------------------------------------------------")
                    print(
                        f"Src:{socket.inet_ntoa(packet.src)}:{segment.src_port}->"
                        f"Dest:{socket.inet_ntoa(packet.dest)}:{segment.dest_port}")
                    print('Data:\n' + segment.data.decode())


if __name__ == '__main__':
    main()
