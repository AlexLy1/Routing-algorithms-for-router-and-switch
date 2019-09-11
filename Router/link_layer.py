#!/usr/bin/env python3

from switchyard.lib.userlib import *

class EthernetProcessor():

    def __init__(self, mac, iface):
        self.mac_address = mac
        self.interface = iface
        self.ipv6 = None
        self.physical = None

    def setstack(self, ip, physical):
        self.ipv6 = ip
        self.physical = physical

    def accept_packet(self, packet_data):

        # remove first header
        eth = packet_data.get_header_by_name("Ethernet")
        del packet_data[0]  


        self.ipv6.accept_packet(packet_data)

    def send_packet(self, packet_data, dst_mac, eType):

        # ethernet type refers to: https://en.wikipedia.org/wiki/EtherType#Examples
        placeholder = 0xffff
        if(eType > 0):
            if(eType == 1):
                placeholder = 0x0800 # stands for ipv4
            elif(eType == 2):
                placeholder = 0x86DD # stands for ipv6
        elif(eType < 0):
            placeholder = 0x0806 # stands for arp
        eth = Ethernet(src=self.mac_address, dst=dst_mac, ethertype=placeholder)
        # create a packet and prepend ethernet header and packet data
        p = Packet() + eth + packet_data
        self.physical.send_packet(self.interface, p)
 
    def __str__(self):
        return "Ethernet link layer ({})".format(self.ipv6_address)
