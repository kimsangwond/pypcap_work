import scapy
from scapy.all import *
#scapy import


def one_packet(packet):
    a = packet.show()
    #sniff함수에게 전달할 패킷을 생성하는 함수

def one_sniff(filter):
    sniff(filter=filter, prn=one_packet, count=2)
    #filter: 원하는 프로토콜만 볼 수 있게 지정/ 삭제 가능
    #prn: packet에 캡쳐한 내용을 sniff에게 전달하는 함수 설정
    #count: packet 캡쳐 개수 지정


if __name__ == '__main__':
    filter = 'ip'
    one_sniff(filter)