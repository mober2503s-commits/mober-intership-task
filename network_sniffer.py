import socket
import struct
import textwrap

def mac_addr(bytes_addr):
    return ':'.join('{:02x}'.format(b) for b in bytes_addr)

def ipv4(addr):
    return '.'.join(map(str, addr))

def sniff():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    packet_count = 0
    tcp_count = 0
    udp_count = 0
    other_count = 0

    print("Listening for packets...")

    try:
        while True:
            raw_data, addr = conn.recvfrom(65536)

            packet_count += 1

            eth_header = raw_data[:14]
            eth = struct.unpack('!6s6sH', eth_header)
            dest_mac = mac_addr(eth[0])
            src_mac = mac_addr(eth[1])
            proto = socket.htons(eth[2])

            print("\n=== Ethernet Frame ===")
            print(f"Packet #: {packet_count}")
            print(f"Destination MAC: {dest_mac}, Source MAC: {src_mac}, Protocol: {proto}")

            if proto == 8:
                ip_header = raw_data[14:34]
                iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                version_ihl = iph[0]
                version = version_ihl >> 4
                ihl = (version_ihl & 0xF) * 4
                ttl = iph[5]
                protocol = iph[6]
                src_ip = ipv4(iph[8])
                dest_ip = ipv4(iph[9])

                print("\n--- IPv4 Packet ---")
                print(f"Version: {version}, Header Length: {ihl} bytes")
                print(f"TTL: {ttl}, Protocol: {protocol}")
                print(f"Source IP: {src_ip}, Destination IP: {dest_ip}")

                if protocol == 6:
                    tcp_count += 1
                    t = 14 + ihl
                    tcp_header = raw_data[t:t+20]
                    tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                    src_port = tcph[0]
                    dest_port = tcph[1]
                    print("\n--- TCP Segment ---")
                    print(f"Source Port: {src_port}, Destination Port: {dest_port}")

                elif protocol == 17:
                    udp_count += 1
                    u = 14 + ihl
                    udp_header = raw_data[u:u+8]
                    udph = struct.unpack('!HHHH', udp_header)
                    src_port = udph[0]
                    dest_port = udph[1]
                    print("\n--- UDP Datagram ---")
                    print(f"Source Port: {src_port}, Destination Port: {dest_port}")

                else:
                    other_count += 1

            if packet_count % 10 == 0:
                print(f"\n{'='*40}")
                print(f"  PACKET SUMMARY (every 10 packets)")
                print(f"  Total  : {packet_count}")
                print(f"  TCP    : {tcp_count}")
                print(f"  UDP    : {udp_count}")
                print(f"  Other  : {other_count}")
                print(f"{'='*40}")

    except KeyboardInterrupt:
        print("\n\nStopped sniffing.")
        print(f"\n{'='*40}")
        print(f"  FINAL PACKET SUMMARY")
        print(f"  Total Packets : {packet_count}")
        print(f"  TCP           : {tcp_count}")
        print(f"  UDP           : {udp_count}")
        print(f"  Other         : {other_count}")
        print(f"{'='*40}")

if __name__ == "__main__":
    sniff()