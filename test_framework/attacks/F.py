# AAAAA...BBB.
# .CCCCCCCCCCC

from scapy.all import IP, TCP, Ether, send, wrpcap

sip = "127.0.0.1"
dip = "127.0.0.1"
sp = 6001
dp = 6000
ISN = 0
ISN_receiver = 1000

a_beg = 0
b_beg = 8
c_beg = 1
x_beg = 6

a_len = 5
b_len = 3
c_len = 11
x_len = 2

a_data = "A" * a_len
b_data = "B" * b_len
c_data = "C" * c_len
x_data = "X" * x_len

packets = []

# === 3 way handshake ===
ip = Ether() / IP(src=sip, dst=dip)
tcp = TCP(dport=dp, sport=sp, flags="S", seq=ISN)
syn = ip / tcp
packets.append(syn)

# craft syn ack
ip_reverse = Ether() / IP(src=dip, dst=sip)
synack_tcp = TCP(dport=sp, sport=dp, flags="SA", seq=ISN_receiver, ack=syn.seq + 1)
synack = ip_reverse / synack_tcp
packets.append(synack)

tcpseq = ISN + 1
myack = ISN_receiver + 1
tcp = TCP(ack=myack, dport=dp, sport=sp, flags="A", seq=tcpseq)
ackit = ip / tcp
packets.append(ackit)

# === begin of data packets ===

# a
tcp = TCP(ack=myack, dport=dp, sport=sp, flags="PA")
tcp.seq = tcpseq + a_beg
pack1 = ip / tcp / a_data
packets.append(pack1)

# ack a
ack_tcp = TCP(ack=tcp.seq + a_len, seq=myack, dport=sp, sport=dp, flags="A")
ack = ip_reverse/ack_tcp
packets.append(ack)

# b
tcp = TCP(ack=myack, dport=dp, sport=sp, flags="PA")
tcp.seq = tcpseq + b_beg
pack2 = ip / tcp / b_data
packets.append(pack2)

# ack b
packets.append(ack) # send same ack as for a because of hole

# c
tcp = TCP(ack=myack, dport=dp, sport=sp, flags="PA")
tcp.seq = tcpseq + c_beg
pack3 = ip / tcp / c_data
packets.append(pack3)

# ack c

tcpseq = tcpseq + c_beg + c_len
ack_tcp = TCP(ack=tcpseq, seq=myack, dport=sp, sport=dp, flags="A")
ack = ip_reverse/ack_tcp
packets.append(ack)

# craft FIN ACK
fin = ip / TCP(sport=sp, dport=dp, flags="FA", seq=tcpseq, ack=myack)
packets.append(fin)

# craft FIN ACK
finack = ip_reverse / TCP(sport=dp, dport=sp, flags="FA", ack=tcpseq + 1, seq=ISN_receiver + 1)
packets.append(finack)

# craft last ACK
lastack = ip / TCP(sport=sp, dport=dp, flags="A", seq=tcpseq, ack=ISN_receiver + 2)
packets.append(lastack)

wrpcap("F.pcap", packets)
