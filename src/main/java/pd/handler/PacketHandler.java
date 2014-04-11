package pd.handler;

import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

import pd.HandlerException;
import pd.view.IView;

public interface PacketHandler
{
    public void recvPacket(int frameId, Ip4 ip4, Tcp tcp, long timestamp) throws HandlerException;

    public void sendPacket(int frameId, Ip4 ip4, Tcp tcp, long timestamp) throws HandlerException;

    public void setView(IView view);

    public void setInfo(int sourceHost, int sourcePort, int destinationHost, int destinationPort);

}
