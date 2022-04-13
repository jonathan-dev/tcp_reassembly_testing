
#..attack
#.......hment
#my

# !/usr/bin/python
def segment(dip):
    sp = 6001
    dp = 6000
    ISN = 10
    ISN_receiver = 1000

    attack_begin = 2
    hment_begin = 7
    my_begin = 0

    attack_data = "attack"
    hment_data = "hment"
    my_data = "my"

    attack_length = len(attack_data)
    hment_length = len(hment_data)
    my_length = len(my_data)


    packets = []

    # 3 way handshake
    ip = Ether() / IP(src=sip, dst=dip)
    tcp = TCP(dport=dp, sport=sp, flags="S", seq=ISN, window=5480, options=[('MSS', 1460)])
    syn = ip / tcp
    packets.append(syn)

    # craft syn ack
    ip_reverse = Ether() / IP(src=dip, dst=sip)
    synack_tcp = TCP(dport=sp, sport=dp, flags="SA", seq=ISN_receiver, ack=syn.seq + 1)
    synack = ip_reverse / synack_tcp
    packets.append(synack)

    tcpseq = ISN + 1
    myack = ISN_receiver + 1
    tcp = TCP(ack=myack, dport=dp, sport=sp, flags="A", seq=tcpseq, window=5480)
    ackit = ip / tcp
    packets.append(ackit)

    # begin of data packets

    # attack
    tcp = TCP(ack=myack, dport=dp, sport=sp, flags="PA", window=5480)
    tcp.seq = tcpseq + attack_begin
    pack1 = ip / tcp / attack_data
    packets.append(pack1)

    ack_tcp = TCP(dport=sp, sport=dp, flags="A", seq=ISN_receiver + 1, ack=tcpseq)  # TODO: note + 1
    ack = ip_reverse / ack_tcp
    packets.append(ack)

    # hment
    tcp = TCP(ack=myack, dport=dp, sport=sp, flags="PA", window=5480)
    tcp.seq = tcpseq + hment_begin
    pack1 = ip / tcp / hment_data
    packets.append(pack1)

    packets.append(ack)

    # my
    tcp = TCP(ack=myack, dport=dp, sport=sp, flags="PA", window=5480)
    tcp.seq = tcpseq + my_begin
    pack1 = ip / tcp / my_data
    packets.append(pack1)

    last_to_ack = tcpseq+hment_begin+hment_length
    ack_tcp.ack = last_to_ack
    ack = ip_reverse / ack_tcp
    packets.append(ack)

    # craft FIN ACK ->
    tcpseq = tcpseq + hment_length + hment_begin
    fin = ip / TCP(sport=sp, dport=dp, flags="FA", seq=tcpseq, ack=last_to_ack)
    packets.append(fin)

    # craft FIN ACK <-
    finack = ip_reverse / TCP(sport=dp, dport=sp, flags="FA", ack=tcpseq + 1, seq=ISN_receiver + 1)
    packets.append(finack)

    # craft last ACK
    lastack = ip / TCP(sport=sp, dport=dp, flags="A", seq=tcpseq + 1, ack=ISN_receiver + 2)
    packets.append(lastack)

    wrpcap("myattackment.pcap", packets)


import random, time, sys
from scapy.all import IP, TCP, Ether, send, wrpcap

dip = "127.0.0.1"
sip = "127.0.0.1"

segment(dip)
