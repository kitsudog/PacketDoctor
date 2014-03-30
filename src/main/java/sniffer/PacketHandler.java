package sniffer;

import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

public interface PacketHandler
{
    public void nextPacket(Ip4 ip4, Tcp tcp, long timestamp);

    public void setOut(IOut out);

}
