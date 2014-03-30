package sniffer.handler;

import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

import sniffer.HandlerException;
import sniffer.view.IView;

public interface PacketHandler
{
    public void nextPacket(Ip4 ip4, Tcp tcp, long timestamp) throws HandlerException;

    public void setView(IView view);

}
