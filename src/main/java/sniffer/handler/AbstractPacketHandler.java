package sniffer.handler;

import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

import sniffer.GiveupException;
import sniffer.HandlerException;
import sniffer.view.IView;

public abstract class AbstractPacketHandler implements PacketHandler
{

    protected IView view;

    @Override
    public void setView(IView view)
    {
        this.view = view;
    }

    @Override
    public void nextPacket(Ip4 ip4, Tcp tcp, long timestamp) throws HandlerException
    {
        if (isDisconect(tcp))
        {
            throw new GiveupException();
        }
    }

    private boolean isDisconect(Tcp tcp)
    {
        if (tcp.flags_FIN())
        {
            return true;
        }
        return false;
    }

}
