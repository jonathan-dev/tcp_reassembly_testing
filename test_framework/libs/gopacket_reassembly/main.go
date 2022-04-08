package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/reassembly"
	"log"
)

var (
	err    error
	handle *pcap.Handle
)

type myStreamFactory struct {
}

type myStream struct {
}

type Context struct {
	CaptureInfo gopacket.CaptureInfo
}

func (stream myStream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, nextSeq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	// We accept every packet since we only have relevant packets in our test
	return true
}

func (stream myStream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	// this function is also triggered when syn or fin packets are received.
	len, _ := sg.Lengths()
	if len != 0 {
		fmt.Print(string(sg.Fetch(len)))
	}
}

func (stream myStream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	// return true to remove connection
	return true
}

func (factory *myStreamFactory) New(net, transport gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {
	return myStream{}
}

func (c *Context) GetCaptureInfo() gopacket.CaptureInfo {
	return c.CaptureInfo
}

type Mode int64

const (
	Interface Mode = iota
	File
)

func main() {

	iface := flag.String("i", "", "the interface")
	file := flag.String("f", "", "the file")

	streamFactory := &myStreamFactory{}
	streamPool := reassembly.NewStreamPool(streamFactory)
	assembler := reassembly.NewAssembler(streamPool)

	flag.Parse()

	var m Mode

	if *iface != "" {
		m = Interface
	} else if *file != "" {
		m = File
	}

	switch m {
	case Interface:
		//handle, err = pcap.OpenLive(*iface, snapshot_len, promiscuous, timeout)
	case File:
		handle, err = pcap.OpenOffline(*file)
	}

	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		tcp := packet.Layer(layers.LayerTypeTCP)
		if tcp != nil {
			tcp := tcp.(*layers.TCP)
			c := Context{
				CaptureInfo: packet.Metadata().CaptureInfo,
			}
			assembler.AssembleWithContext(packet.NetworkLayer().NetworkFlow(), tcp, &c)
			//fmt.Println("%s\n", packet.NetworkLayer().NetworkFlow(), c.CaptureInfo)
		}
	}
}
