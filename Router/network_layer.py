#!/usr/bin/env python3

from switchyard.lib.userlib import *

class IpProcessor():

    def __init__(self, inet6, inet4):
        self.ipv6_address = inet6
        self.ipv4_address = inet4
        self.stopandwait = None
        self.ethernet = None
        
        self.ipv6_2mac = dict()
        self.ipv4_2mac = dict()

    def setstack(self, ethernet, stopandwait):
        self.ethernet = ethernet
        self.stopandwait = stopandwait

    def accept_packet(self, packet_data):
        # log_debug("IpProcessor received packet from below")
        if(packet_data.has_header(IPv4)):
            # handling received packet is based on IPv4 protocol
            print("received ipv4")
            ipv4Header = packet_data.get_header_by_name("IPv4")
            print("ipv4 dst: " + str(ipv4Header.dst))
            print("ipv4 self: " + str(self.ipv4.address))
            if(ipv4Header.dst == self.ipv4.address):
                print("The message supposed to send to here!")
                print("Message from: ", ipv4Header.src)
                print("ipv4 message received passing up to transport layer")
                del packet_data[0]
                self.stopandwait.accept_packet(packet_data, ipv4Header.src)
        elif(packet_data.has_header(IPv6)):
            # handling received packet base on IPv6 protocol
            print("received ipv6")
            ipv6Header = packet_data.get_header_by_name("IPv6")
            if(ipv6Header.nextheader == IPProtocol.ICMPv6):
                # received a NDP message
                self.processICMPv6(packet_data, ipv6Header.src, ipv6Header.dst)
            elif(ipv6Header.dst == self.ipv6_address):
                print("IPV6 message received passing up to transport layer")
                del packet_data[0]
                self.stopandwait.accept_packet(packet_data, ipv6Header.src)
        elif(packet_data.has_header(Arp)):
            # handling arp response sent by IPv4
            print("received ipv4 Arp message")
            arpPacket = packet_data.get_header_by_name("Arp")
            if(arpPacket.senderprotoaddr not in self.ipv4_2mac):
                # receive a packet with unknown ip address
                # Add this new IP address and its mac address into the ARP table
                print("New entry to IPv4 map: ", arpPacket.senderprotoaddr)
                self.ipv4_2mac[IPv4Address(arpPacket.senderprotoaddr)] = EthAddr(arpPacket.senderhwaddr)
            if(arpPacket.targetprotoaddr == self.ipv4_address):
                if(arpPacket.operation == ArpOperation.Reply):
                    print("It's an arp reply message")
                elif(arpPacket.operation == ArpOperation.Request):
                    # detecting this arp packet is a arp boardcast packet
                    # create a arp replay packet and send it back to the sender node 
                    arpReplyObject = self.create_arp_reply(arpPacket)
                    print("It's an arp request message")
                    self.ethernet.send_packet(arpReplyObject, arpPacket.senderhwaddr, -1) ## fufill methods 


    def send_packet(self, packet_data, dst_ip):
        # log_debug("IpProcessor received packet to be sent")

        if type(dst_ip) == type(IPv6Address("0::0")):
            
            if dst_ip not in self.ipv6_2mac:
                ipv6Object = self.create_ipv6_Object(dst_ip, True)
                ipv6Solicit = self.create_solicitation(dst_ip)
                self.ethernet.send_packet(ipv6Object + ipv6Solicit, "FF:FF:FF:FF:FF:FF", 2)
            else:
                ipv6Object = self.create_ipv6_Object(dst_ip, False)
                self.ethernet.send_packet(ipv6Object + packet_data, self.ipv6_2mac[dst_ip], 2)

        if type(dst_ip) == type(IPv4Address("0.0.0.0")):
            
            if dst_ip not in self.ipv4_2mac:
                # if there is no matching destination address
                # create an Arp request object
                # boardcast the Arp request object with address 'FF:FF:FF:FF:FF:FF'
                arpObject = self.create_arp_Object(dst_ip)
                self.ethernet.send_packet(arpObject, "FF:FF:FF:FF:FF:FF", -1) # -1 indicates arp ethernet type
            else: 
                # create an ipv4 packet with this source ip address and the packet data
                # creating the ipv4 packet can be referred to ipv4.py in switchyard/lib/packet
                ipv4Object = IPv4(src = self.ipv4_address, dst=dst_ip, protocl=IPProtocol.UDP)
                self.ethernet.send_packet(ipv4Object + packet_data, self.ipv4_2mac[dst_ip], 1) # 1 indicates ipv4 ethernet type
        self.print_map()
    
    # This method is for printing out the map of the switch 
    # brorrow code from: https://github.com/rafa-ela/NWEN-302-LAB2/blob/master/network_layer.py
    def print_map(self):  
        '''prints out the values and size of the map '''
        if(len(self.ipv6_2mac) !=0):
            print(" ------------------------------------- ")
            print("        IPV6 Map size ",len(self.ipv6_2mac))
            for k, v in self.ipv6_2mac.items():
                print("  -------------------------------------- ")
                print("  ",k, v)
        elif(len(self.ipv4_2mac) !=0):
            print("  -------------------------------------- ")
            print("     IPV4 Map size:    ", len(self.ipv4_2mac))
            for k, v in self.ipv4_2mac.items():
                print("  -------------------------------------- ")
                print("  ",k, v)
        print("  -------------------------------------- ")
    
    # This method is for creating an Arp object
    def create_arp_Object(self, destinationIP):
        # creat an arp request packet
        # constructure an arp object, refer to arp.py in swtichyard/lib/packet
        arpObject = Arp(operation = ArpOperation.Request, 
                        senderhwaddr = self.ethernet.mac_address, senderprotoaddr = self.ipv4_address,
                        targethwaddr = "FF:FF:FF:FF:FF:FF", targetprotoaddr = destinationIP)
        return arpObject
    
    # This method is for creating an Arp reply object
    def create_arp_reply(self, arpPacket):
        ## creating a arp reply packet, which will be sent back to the boardcast sender
        arpReply = Arp(operation = ArpOperation.Reply, 
                       senderhwaddr = self.ethernet.mac_address, senderprotoaddr = self.ipv4_address,
                       targethwaddr = arpPacket.senderhwaddr, targetprotoaddr = arpPacket.senderprotoaddr)
        return arpReply

    # This method is for creating an ipv6 object
    def create_ipv6_Object(self, destinationIP, boardcast):
        # referred to ipv6.py in lab1/parta/switchyard/lib/packet
        ipv6Object = IPv6(dst=destinationIP, src=self.ipv6_address)
        if(boardcast == False):
            # use UDP protocol to do normal packet sending
            ipv6Object.nextheader = IPProtocol.UDP
        else:
            # use ICMPv6 to do NDP
            ipv6Object.nextheader = IPProtocol.ICMPv6
        return ipv6Object
    
    # process the ipv6 boardcast packet 
    def processICMPv6(self, packet, srcIP, destIP):
        header = packet.get_header_by_name("ICMPv6")
        srcMacAddress = header.icmpdata.options[0]._linklayeraddress
        if(srcIP not in self.ipv6_2mac):
            print("Added a new entry to IPv6 table: ", srcIP)
            self.ipv6_2mac[IPv6Address(srcIP)] = EthAddr(srcMacAddress)
        if(destIP == self.ipv6_address):
            if(header.icmptype == ICMPv6Type.NeighborSolicitation):
                print("ICMPv6 message was a solicitation")
                # make an advertisement and send it back to the source host 
                ipv6Advertisement = self.create_ipv6_Advertisement(srcIP)
                ipv6Reply = self.create_ipv6_Object(srcIP, True)
                self.ethernet.send_packet(ipv6Reply+ipv6Advertisement, srcMacAddress, 2)
            else:
                print("ICMPv6 message was an advertisement")
                
    # This method is for creating an ICMPv6 solicitation header 
    def create_solicitation(self, destinationIP):
        print("creating a solicitation header")
        icmpv6 = ICMPv6(icmptype = ICMPv6Type.NeighborSolicitation)
        icmpv6_solit = ICMPv6NeighborSolicitation(targetaddr=destinationIP)
        icmpv6_solit.options.append(ICMPv6OptionSourceLinkLayerAddress(self.ethernet.mac_address))
        icmpv6.icmpdata = icmpv6_solit
        return icmpv6
    
    def create_ipv6_Advertisement(self, srcIP):
        print("Creating an advertisement header")
        icmpv6 = ICMPv6(icmptype=ICMPv6Type.NeighborAdvertisement)
        advertisement = ICMPv6NeighborAdvertisement(targetaddr = srcIP)
        advertisement.options.append(ICMPv6OptionTargetLinkLayerAddress(self.ethernet.mac_address))
        icmpv6.icmpdata = advertisement
        return icmpv6
    
    def __str__(self):
        return "IP network layer ({} & {})".format(self.ipv6_address, self.ipv4_address)

