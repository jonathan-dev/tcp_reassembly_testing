# ------------------------------------------------------------------------
#
# Copyright (C) 2022 Jonathan Drude
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License Version 2 as
# published by the Free Software Foundation. You may not use, modify or
# distribute this program under any other version of the GNU General
# Public License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
#
# This file incorporates work covered by the following copyright and
# permission notice:
#
#    Copyright (C) 2007 Judy Novak
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License Version 2 as
#    published by the Free Software Foundation. You may not use, modify or
#    distribute this program under any other version of the GNU General
#    Public License.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
#
# ------------------------------------------------------------------------
# !/usr/bin/python
def segment(dip):
    sp = 6001
    dp = 6000
    ISN = 10
    ISN_receiver = 1000
    P0 = "0"
    P1 = "A"
    P2 = "B"
    P3 = "C"
    P3_1 = "D"
    P3_2 = "E"
    P3_3 = "F"
    P3_4 = "G"
    P3_5 = "H"
    P3_6 = "I"
    P4 = "J"
    P5 = "K"
    P6 = "L"
    P7 = "M"
    P8 = "N"
    P9 = "O"
    P10 = "P"
    P11 = "Q"

    p1_seqplus = 1
    p2_seqplus = 5
    p3_seqplus = 7
    p3_1_seqplus = 11
    p3_2_seqplus = 14
    p3_3_seqplus = 16
    p3_4_seqplus = 19
    p3_5_seqplus = 21
    p3_6_seqplus = 23
    p4_seqplus = 2
    p5_seqplus = 7
    p6_seqplus = 10
    p7_seqplus = 13
    p8_seqplus = 17
    p9_seqplus = 20
    p10_seqplus = 21
    p11_seqplus = 23
    p12_seqplus = 25

    seg0 = P0
    seg1 = P1 * 3
    seg2 = P2 * 2
    seg3 = P3 * 3
    seg3_1 = P3_1
    seg3_2 = P3_2 * 2
    seg3_3 = P3_3 * 3
    seg3_4 = P3_4 * 2
    seg3_5 = P3_5 * 2
    seg3_6 = P3_6
    seg4 = P4 * 4
    seg5 = P5 * 3
    seg6 = P6 * 3
    seg7 = P7 * 3
    seg8 = P8
    seg9 = P9
    seg10 = P10
    seg11 = P11 * 2

    packets = []

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

    tcp = TCP(ack=myack, dport=dp, sport=sp, flags="PA", window=5480)
    tcp.seq = tcpseq + p1_seqplus
    pack1 = ip / tcp / seg1
    packets.append(pack1)

    ack_tcp = TCP(dport=sp, sport=dp, flags="A", seq=ISN_receiver+1, ack=tcpseq) # TODO: note + 1
    ack = ip_reverse / ack_tcp
    packets.append(ack)

    tcp.seq = tcpseq + p2_seqplus
    pack2 = ip / tcp / seg2
    packets.append(pack2)

    packets.append(ack)

    tcp.seq = tcpseq + p3_seqplus
    pack3 = ip / tcp / seg3
    packets.append(pack3)

    packets.append(ack)

    tcp.seq = tcpseq + p3_1_seqplus
    pack3_1 = ip / tcp / seg3_1
    packets.append(pack3_1)

    packets.append(ack)

    tcp.seq = tcpseq + p3_2_seqplus
    pack3_2 = ip / tcp / seg3_2
    packets.append(pack3_2)

    packets.append(ack)

    tcp.seq = tcpseq + p3_3_seqplus
    pack3_3 = ip / tcp / seg3_3
    packets.append(pack3_3)

    packets.append(ack)

    tcp.seq = tcpseq + p3_4_seqplus
    pack3_4 = ip / tcp / seg3_4
    packets.append(pack3_4)

    packets.append(ack)

    tcp.seq = tcpseq + p3_5_seqplus
    pack3_5 = ip / tcp / seg3_5
    packets.append(pack3_5)

    packets.append(ack)

    tcp.seq = tcpseq + p3_6_seqplus
    pack3_6 = ip / tcp / seg3_6
    packets.append(pack3_6)

    packets.append(ack)

    tcp.seq = tcpseq + p4_seqplus
    pack4 = ip / tcp / seg4
    packets.append(pack4)

    packets.append(ack)

    tcp.seq = tcpseq + p5_seqplus
    pack5 = ip / tcp / seg5
    packets.append(pack5)

    packets.append(ack)

    tcp.seq = tcpseq + p6_seqplus
    pack6 = ip / tcp / seg6
    packets.append(pack6)

    packets.append(ack)

    tcp.seq = tcpseq + p7_seqplus
    pack7 = ip / tcp / seg7
    packets.append(pack7)

    packets.append(ack)

    tcp.seq = tcpseq + p8_seqplus
    pack8 = ip / tcp / seg8
    packets.append(pack8)

    packets.append(ack)

    tcp.seq = tcpseq + p9_seqplus
    pack9 = ip / tcp / seg9
    packets.append(pack9)

    packets.append(ack)

    tcp.seq = tcpseq + p10_seqplus
    pack10 = ip / tcp / seg10
    packets.append(pack10)

    packets.append(ack)

    tcp.seq = tcpseq + p11_seqplus
    pack11 = ip / tcp / seg11
    packets.append(pack11)

    packets.append(ack)

    tcp.seq = tcpseq
    pack0 = ip / tcp / seg0
    packets.append(pack0)

    # craft FIN ACK
    tcpseq = tcpseq + p12_seqplus
    fin = ip / TCP(sport=sp, dport=dp, flags="FA", seq=tcpseq, ack=myack)
    packets.append(fin)

    # craft FIN ACK
    finack = ip_reverse / TCP(sport=dp, dport=sp, flags="FA", ack=tcpseq + 1, seq=ISN_receiver + 1)
    packets.append(finack)

    # craft last ACK
    lastack = ip / TCP(sport=sp, dport=dp, flags="A", seq=tcpseq+1, ack=ISN_receiver + 2)
    packets.append(lastack)

    wrpcap("sturges-novak-model.pcap", packets)


import random, time, sys
from scapy.all import IP, TCP, Ether, send, wrpcap

dip = "192.168.8.29"
sip = "192.168.8.31"

segment(dip)
