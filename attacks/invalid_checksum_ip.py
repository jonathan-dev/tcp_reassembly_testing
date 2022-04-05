# !/usr/bin/python

# AAABBBCCC


def segment(dip):
    sp = 6001
    dp = 6000
    ISN = 10
    ISN_receiver = 1000

    a_begin = 0
    b_begin = 3
    c_begin = 6
    x_begin = 3

    a_length = 3
    b_length = 3
    c_length = 3
    x_length = 3

    a_data = "A" * a_length
    b_data = "B" * b_length
    c_data = "C" * c_length
    x_data = "X" * x_length

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

    # ack
    tcpseq = ISN + 1
    myack = ISN_receiver + 1
    tcp = TCP(ack=myack, dport=dp, sport=sp, flags="A", seq=tcpseq, window=5480)
    ackit = ip / tcp
    packets.append(ackit)

    # begin of data packets

    # a
    tcp = TCP(ack=myack, dport=dp, sport=sp, flags="PA", window=5480)
    tcp.seq = tcpseq + a_begin
    pack1 = ip / tcp / a_data
    packets.append(pack1)

    # ack
    remote_ack = TCP(dport=sp, sport=dp, flags="A", seq=ISN_receiver + 1)
    remote_ack.ack = tcp.seq + a_length
    remote_ack_packet = ip_reverse/remote_ack
    packets.append(remote_ack_packet)

    # b
    ip_wrong_checksum = Ether() / IP(src=sip, dst=dip, chksum=0)
    tcp = TCP(ack=myack, dport=dp, sport=sp, flags="PA", window=5480)
    tcp.seq = tcpseq + b_begin
    pack1 = ip_wrong_checksum / tcp / b_data
    packets.append(pack1)

    # x
    tcp = TCP(ack=myack, dport=dp, sport=sp, flags="PA", window=5480)
    tcp.seq = tcpseq + x_begin
    packx = ip / tcp / x_data
    packets.append(packx)

    # ack
    remote_ack.ack = tcp.seq + x_length
    remote_ack_packet = ip_reverse / remote_ack
    packets.append(remote_ack_packet)

    # c
    tcp = TCP(ack=myack, dport=dp, sport=sp, flags="PA", window=5480)
    tcp.seq = tcpseq + c_begin
    pack1 = ip / tcp / c_data
    packets.append(pack1)

    # ack
    remote_ack.ack = tcp.seq + c_length
    remote_ack_packet = ip_reverse / remote_ack
    packets.append(remote_ack_packet)

    # craft FIN
    tcpseq = tcpseq + c_begin + c_length
    fin = ip / TCP(sport=sp, dport=dp, flags="FA", seq=tcpseq, ack=myack)
    packets.append(fin)

    # craft FIN ACK
    finack = ip_reverse / TCP(sport=dp, dport=sp, flags="FA", ack=tcpseq + 1, seq=ISN_receiver + 1)
    packets.append(finack)

    # craft last ACK
    lastack = ip / TCP(sport=sp, dport=dp, flags="A", seq=tcpseq, ack=ISN_receiver + 2)
    packets.append(lastack)

    wrpcap("invalid_checksum_ip.pcap", packets)


from scapy.all import IP, TCP, Ether, send, wrpcap

dip = "127.0.0.1"
sip = "127.0.0.1"

segment(dip)
