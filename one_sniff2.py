#!/usr/bin/python
# -*- coding: cp949 -*-b
# -*- coding:utf-8 -*-


from scapy.all import*
import ifaddr

def one_packet(packet):
    src_add = packet[0][1].src
    #source address
    dst_add = packet[0][1].dst
    #destination address
    proto = packet[0][1].proto
    #protocol type
    
    print ("protocol: %s, source: %s, destination: %s" %(proto, src_add, dst_add))


def one_sniff(filte, iface):
    sniff(iface=iface, filter=filte, prn=one_packet)


if __name__ == '__main__':
    adapters = ifaddr.get_adapters()
    for adapter in adapters:
        print ("IPs of network adapter " + adapter.nice_name)
        for ip in adapter.ips:
            print ("   %s/%s" % (ip.ip, ip.network_prefix))

    conf.iface = input('input nic: ')
    print ("ip")
    print ("tcp")
    print ("udp")
    filte = input('input protocol: ')
    one_sniff(filte, conf.iface)