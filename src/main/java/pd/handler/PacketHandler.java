package pd.handler;

import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

import pd.exception.HandlerException;
import pd.view.IView;

public interface PacketHandler
{
    void recvPacket(int frameNum, Ip4 ip4, Tcp tcp, long timestamp) throws HandlerException;

    void sendPacket(int frameNum, Ip4 ip4, Tcp tcp, long timestamp) throws HandlerException;

    void setView(IView view);

    void setInfo(int sourceHost, int sourcePort, int destinationHost, int destinationPort);

}
