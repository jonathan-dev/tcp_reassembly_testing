/*
 * Copyright (c) 2016, Matias Fontanini
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following disclaimer
 *   in the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <string>
#include <iostream>
#include <boost/regex.hpp>
#include "tins/tcp_ip/stream_follower.h"
#include "tins/sniffer.h"

using std::string;
using std::cout;
using std::cerr;
using std::endl;
using std::exception;

using boost::regex;
using boost::match_results;

using Tins::Packet;
using Tins::Sniffer;
using Tins::FileSniffer;
using Tins::SnifferConfiguration;
using Tins::TCPIP::Stream;
using Tins::TCPIP::StreamFollower;


void on_server_data(Stream &stream) {
    cout << "on server data" << endl;
    cout << stream.server_payload().data() << endl;
}

string convertToString(std::vector<uint8_t> v)
{
    int i;
    string s;
    for (i = 0; i < v.size(); i++) {
        s += char(v[i]);
    }
    return s;
}

void on_client_data(Stream &stream) {
//    cout << "on client data!" << endl;
    cout << convertToString(stream.client_payload());
}

void on_new_connection(Stream &stream) {
    stream.client_data_callback(&on_client_data);
    stream.server_data_callback(&on_server_data);
}

enum mode {
    Interface, File
};

int main(int argc, char *argv[]) {
    enum mode m;

    if (argc > 1){
        if (strcmp(argv[1], "-i") == 0) {
            m = Interface;
        } else if (strcmp(argv[1], "-f") == 0) {
            m = File;
        }else {
            cout << "Usage: " << argv[0] << "-i/-f Interface name/ pcap filename";
            exit(0);
        }
    }else {
        cout << "Usage: " << argv[0] << "-i/-f Interface name/ pcap filename";
        exit(0);
    }

    try {
        // Construct the sniffer configuration object
        SnifferConfiguration config;

        StreamFollower follower;
        follower.new_stream_callback(&on_new_connection);

        // Construct the Sniffer depending on the command line arguments
        switch (m) {
            case mode::Interface: {
                Sniffer sniffer(argv[2], config);

                sniffer.sniff_loop([&](Packet &packet) {
                    follower.process_packet(packet);
                    return true;
                });
            }
            case mode::File: {
                FileSniffer fileSniffer(argv[2], config);

                fileSniffer.sniff_loop([&](Packet &packet) {
                    follower.process_packet(packet);
                    return true;
                });
            }
        }
    }
    catch (exception &ex) {
        cerr << "Error: " << ex.what() << endl;
        return 1;
    }
}
