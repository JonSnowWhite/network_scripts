from scapy.all import *
from scapy.layers.inet import TCP, IP
from scapy.layers.inet6 import IPv6
import threading

#######################################################
#                                                     #
#   Censors http connections using Scapy              #
#                                                     #
#######################################################

FORBIDDEN = "bellenberg"

def censor(pkt: Packet):
    if TCP not in pkt:
        # print("no TCP in TCP filtered packet")
        return
    if IP in pkt:
        ip_layer = IP
    elif IPv6 in pkt:
        ip_layer = IPv6
    else:
        # print("no IP in TCP filtered packet")
        return
    try:
        # read tcp payload from packet in bytes
        payload_bytes = bytes(pkt[TCP].payload)
    except:
        # print("Could not read payload from packet")
        return

    if not payload_bytes or len(payload_bytes) == 0:
        # print("Payload is empty")
        return

    # decode payload with ascii
    try:
        # some sanitization to prevent too easy HTTP bypasses
        payload = payload_bytes.decode("ascii").lower().replace(" ","").replace("\n","").replace("\r","")
    except Exception:
        # print("Could not convert payload to ascii")
        return


    # print(f"Got payload: {payload}")

    # if payload contains forbidden string, censor it
    if "http" in payload and FORBIDDEN in payload:
        print("censoring packet")
        inject_tcp_rst(pkt, ip_layer, len(payload_bytes))

def inject_tcp_rst(pkt: Packet, layer, p_len: int):
    # get src ip and src port
    src_ip = pkt[layer].src
    src_port = pkt[layer].sport
    dst_ip = pkt[layer].dst
    dst_port = pkt[layer].dport
    ack = pkt[TCP].ack
    seq = pkt[TCP].seq

    # craft tcp reset packets to both parties
    srv_rst_ip = layer(dst=dst_ip, src=src_ip)
    srv_rst_tcp = TCP(sport=src_port,
                      dport=dst_port,
                      ack=ack,
                      seq=seq+p_len,
                      flags="R")
    srv_rst = srv_rst_ip/srv_rst_tcp
    clt_rst_ip = layer(dst=src_ip, src=dst_ip)
    clt_rst_tcp = TCP(sport=src_port,
                        dport=dst_port,
                        ack=seq+p_len,
                        seq=ack,
                        flags="R")
    clt_rst = clt_rst_ip/clt_rst_tcp

    # change sequence number


    # send both packets
    for i in range(4):
        threading.Thread(target=send, args=(srv_rst), kwargs={"verbose": 0}).start()
        threading.Thread(target=send, args=(clt_rst), kwargs={"verbose": 0}).start()

    print("censored packet")

conf.layers.filter([IP, IPv6, TCP])
while True:
    # filter for tcp, defrag ip, send to censor
    sniff(filter="tcp", session=IPSession, prn=lambda pkt: censor(pkt))

