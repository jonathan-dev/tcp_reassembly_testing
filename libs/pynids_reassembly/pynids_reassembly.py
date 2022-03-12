#! /usr/bin/env python2

import os, pwd
# TODO: replace getopt
import sys, getopt
import nids

NOTROOT = "nobody"  # edit to taste
end_states = (nids.NIDS_CLOSE, nids.NIDS_TIMEOUT, nids.NIDS_RESET)

def handleTcpStream(tcp):
    if tcp.nids_state == nids.NIDS_JUST_EST:
        tcp.client.collect = 1
        tcp.server.collect = 1
    elif tcp.nids_state == nids.NIDS_DATA:
        sys.stdout.write(tcp.server.data[:tcp.server.count_new])  # WARNING - may be binary
        tcp.discard(tcp.server.count_new)


def main():
    nids.param("pcap_filter", "tcp")  # bpf restrict to TCP only, note
    # libnids caution about fragments

    nids.param("scan_num_hosts", 0)  # disable portscan detection
    nids.chksum_ctl([('0.0.0.0/0', False)])  # disable checksumming

    try:
        opts, args = getopt.getopt(sys.argv[1:], "i:f:")
    except getopt.GetoptError:
        # print help information and exit:
        # usage()
        sys.exit(2)

    for o, a in opts:
        if o == "-i":
            nids.param("device", a)
        elif o == "-f":
            nids.param("filename", a)

    nids.init()

    # # drop root privileges
    # (uid, gid) = pwd.getpwnam(NOTROOT)[2:4]
    # os.setgroups([gid, ])
    # os.setgid(gid)
    # os.setuid(uid)
    # if 0 in [os.getuid(), os.getgid()] + list(os.getgroups()):
    #     print "error - drop root, please!"
    #     sys.exit(1)

    nids.register_tcp(handleTcpStream)

    # Loop forever (network device), or until EOF (pcap file)
    # Note that an exception in the callback will break the loop!
    try:
        nids.run()
    except nids.error as e:
        print ("nids/pcap error:", e)
    except Exception as e:
        print ("misc. exception (runtime error in user callback?):", e)


if __name__ == '__main__':
    main()
