#!/usr/bin/python  
# -*- coding: cp949 -*-b
# -*- coding:utf-8 -*-


from scapy.all import*  
  
def one_packet(packet):
    src_add = packet[0][1].src  
    #source address
    dst_add = packet[0][1].dst 
    #destination address 
    proto = packet[0][1].proto  
    #protocol type
  
    print ("protocol: %s, source: %s, destination: %s" %(proto, src_add, dst_add))
  
  
def one_sniff(filte, iface):
    sniff(iface=iface, filter=filte, prn=one_packet, count=20)

  
if __name__ == '__main__': 
    conf.iface = input('input nic: ')
    filte = input('input protocol: ')
    one_sniff(filte, conf.iface)