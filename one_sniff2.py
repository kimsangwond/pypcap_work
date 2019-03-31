#!/usr/bin/python  
from scapy.all import*  
  
  
def one_packet(packet):
    src_add = packet[0][1].src  
    #source address
    dst_add = packet[0][1].dst 
    #destination address 
    proto = packet[0][1].proto  
    #protocol type
  
    print ("protocol: %s, source: %s, destination: %s" %(proto, src_add, dst_add))
  
  
def one_sniff(filter):
    sniff(filter=filter, prn=one_packet, count=20)
    #filter: 원하는 프로토콜만 볼 수 있게 지정/ 삭제 가능
    #prn: packet에 캡쳐한 내용을 sniff에게 전달하는 함수 설정
    #count: packet 캡쳐 개수 지정

  
if __name__ == '__main__':  
    filter = 'ip'
    one_sniff(filter)  
