'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
from switchyard.lib.userlib import *

# Create a dictionary to store macaddress-interface mappings. 
macadd_2port = dict()
TTL = 150
dict_maxSize = 5

def main(net):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]


    while True:
        try:
            timestamp,input_port,packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return

        log_debug ("In {} received packet {} on {}".format(net.name, packet, input_port))

        # Learning process happens here.
        # Before adding new entry into the map, need to make sure there is space for the new entry.
        CreateSpaceForNewEntry();
        # For each instance in the dict: {"dst_mac": ["interface", "TTL"]}
        macadd_2port[packet[0].src] = [input_port, TTL]

        if packet[0].dst in mymacs:
            log_debug ("Packet intended for me")
            # do nothing
        else:
            if packet[0].dst in macadd_2port:
                # packet destination mac address is known, send to this specific address.
                # update TTL for each entry in the map.
                print("Sending packet to a known host!")
                net.send_packet(macadd_2port[packet[0].dst][0], packet)
                # update TTL for each entry in the map
                updateTTL(packet[0].dst)
            else:
                # packet destination is unknown, so do boardcasting.
                print("Floding packet")
                for intf in my_interfaces:
                    if input_port != intf.name:
                        log_debug ("Flooding packet {} to {}".format(packet, intf.name))
                        net.send_packet(intf.name, packet)
    net.shutdown()


'''
    This method is for creating space for new rule when the map is full.
'''
def CreateSpaceForNewEntry():
    if len(macadd_2port) != dict_maxSize:
        return
    else:
        # Map is full.
        # Get the oldest entry in the dict and delete it.
        oldestTTL = 150
        oldestEntry = 0
        for key, entry in macadd_2port.items():
            if entry[1] <= oldestTTL:
                oldestTTL = entry[1]
                oldestEntry = key
        del macadd_2port[oldestEntry]

'''
    This method is for updating TTL for each entry in the map.
'''
def updateTTL(aim):
    for key, entry in macadd_2port.items():
        if key == aim:
            # refresh the TTL of this entry
            entry[1] = TTL
        else:
            # record the last time for the rest entries
            entry[1] -= 5
            if entry[1] <= 0:
                # over time, delete this entry from map.
                del macadd_2port[key]
