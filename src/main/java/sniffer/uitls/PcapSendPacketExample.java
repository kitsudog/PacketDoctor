package sniffer.uitls;

import java.util.ArrayList;
import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapIf;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.winpcap.WinPcap;
import org.jnetpcap.winpcap.WinPcapSendQueue;

public class PcapSendPacketExample
{
    public static void main(String[] args) throws InterruptedException
    {
        List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with
                                                        // NICs
        StringBuilder errbuf = new StringBuilder(); // For any error msgs

        int r = Pcap.findAllDevs(alldevs, errbuf);
        if (r == Pcap.NOT_OK || alldevs.isEmpty())
        {
            System.err.printf("Can't read list of devices, error is %s", errbuf.toString());
            return;
        }
        PcapIf device = alldevs.get(2); // We know we have atleast 1 device

        int snaplen = 64 * 1024; // Capture all packets, no trucation
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
        int timeout = 10 * 1000; // 10 seconds in millis
        WinPcap pcap = WinPcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
        while (true)
        {
            WinPcapSendQueue queue = WinPcap.sendQueueAlloc(512);
            PcapHeader hdr = new PcapHeader(128, 128);
            byte[] http = new byte[]
            { 0x5c, 0x63, (byte) 0xbf, (byte) 0xf3, 0x42, 0x60, 0x10, 0x40, (byte) 0xf3, (byte) 0x93, (byte) 0xf3, 0x12, 0x08, 0x00, 0x45, 0x00, 0x00,
                    (byte) 0xdd, 0x4b, (byte) 0xf6, 0x40, 0x00, (byte) 0x80, 0x06, 0x61, 0x36, (byte) 0xc0, (byte) 0xa8, 0x01, 0x0a, 0x7c, 0x0e, 0x0f, 0x2e,
                    (byte) 0x9a, 0x40, 0x00, 0x50, 0x38, (byte) 0x8f, (byte) 0xe5, 0x3b, (byte) 0xad, 0x5e, (byte) 0xec, 0x53, 0x50, 0x18, 0x01, 0x02,
                    (byte) 0xce, (byte) 0x8d, 0x00, 0x00, 0x47, 0x45, 0x54, 0x20, 0x2f, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x2f, 0x33, 0x64, 0x38, 0x30, 0x34,
                    0x61, 0x65, 0x32, 0x63, 0x30, 0x64, 0x65, 0x65, 0x61, 0x31, 0x33, 0x38, 0x36, 0x38, 0x61, 0x39, 0x37, 0x62, 0x33, 0x66, 0x39, 0x61, 0x30,
                    0x35, 0x65, 0x61, 0x39, 0x31, 0x32, 0x39, 0x39, 0x33, 0x2e, 0x67, 0x69, 0x66, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x0d,
                    0x0a, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x3a, 0x20, 0x2a, 0x2f, 0x2a, 0x0d, 0x0a, 0x55, 0x73, 0x65, 0x72, 0x2d, 0x41, 0x67, 0x65, 0x6e,
                    0x74, 0x3a, 0x20, 0x4d, 0x6f, 0x7a, 0x69, 0x6c, 0x6c, 0x61, 0x2f, 0x34, 0x2e, 0x30, 0x20, 0x28, 0x63, 0x6f, 0x6d, 0x70, 0x61, 0x74, 0x69,
                    0x62, 0x6c, 0x65, 0x3b, 0x20, 0x4d, 0x53, 0x49, 0x45, 0x20, 0x36, 0x2e, 0x30, 0x3b, 0x20, 0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x20,
                    0x4e, 0x54, 0x20, 0x35, 0x2e, 0x31, 0x29, 0x0d, 0x0a, 0x48, 0x6f, 0x73, 0x74, 0x3a, 0x20, 0x63, 0x61, 0x2e, 0x67, 0x74, 0x69, 0x6d, 0x67,
                    0x2e, 0x63, 0x6f, 0x6d, 0x0d, 0x0a, 0x50, 0x72, 0x61, 0x67, 0x6d, 0x61, 0x3a, 0x20, 0x6e, 0x6f, 0x2d, 0x63, 0x61, 0x63, 0x68, 0x65, 0x0d,
                    0x0a, 0x0d, 0x0a };

            queue.queue(hdr, http); // Packet #1
            queue.queue(hdr, http); // Packet #2

            r = pcap.sendQueueTransmit(queue, WinPcap.TRANSMIT_SYNCH_ASAP);
            if (r != queue.getLen())
            {
                System.err.println(pcap.getErr());
            }
            Thread.sleep(100);
        }
    }
}