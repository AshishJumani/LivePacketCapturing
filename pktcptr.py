from scapy.all import sniff,Ether,IP,TCP,UDP
from pyshark import tshark



def packet_handler(packet):
    if packet.haslayer(Ether):
        # Get the Ethernet header
        eth_header = packet[Ether]

        # Check if it's an IP packet
        if eth_header.type == 0x0800:  # IPv4
            ip_header = packet[IP]
            print ("Capturing packet data")

            # Check if it's a TCP packet
            if ip_header.proto == 6:  # TCP
                tcp_header = packet[TCP]

                # Print the TCP source and destination ports
                print("TCP Source Port:", tcp_header.sport)
                print("TCP Destination Port:", tcp_header.dport)   
               

            # Check if it's a UDP packet
            elif ip_header.proto == 17:  # UDP
                udp_header = packet[UDP]

                # Print the UDP source and destination ports
                print("UDP Source Port:", udp_header.sport)
                print("UDP Destination Port:", udp_header.dport)
                        

        print("*****************************")
tshark_path = "C:/Program Files/Wireshark/tshark.exe"
# Start capturing packets

sniff(prn=packet_handler, filter="ip", store=0)



  