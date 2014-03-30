package sniffer.handler;

import java.util.HashMap;

import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

import sniffer.HandlerException;
import sniffer.StopException;

public class TcpHandler extends AbstractPacketHandler

{
    class PacketData
    {

        public PacketData(Ip4 ip4, Tcp tcp)
        {
            this.ip4 = ip4;
            this.tcp = tcp;
            timestamp = ip4.getPacket().getCaptureHeader().timestampInMillis();
            length = tcp.getPayloadLength();
        }

        Ip4 ip4;

        Tcp tcp;

        long timestamp;

        long length;
    }

    private HashMap<Long, PacketData> buffMap = new HashMap<Long, PacketData>();

    private long nextSeq = 0;

    @Override
    final public void nextPacket(Ip4 ip4, Tcp tcp, long timestamp) throws HandlerException
    {
        super.nextPacket(ip4, tcp, timestamp);
        if (!tcp.flags_ACK())
        {
            return;
        }
        if (nextSeq == 0)
        {
            nextSeq = tcp.seq();
        }
        else if (tcp.flags_PSH())
        {
            nextSeq = 0;
        }
        if (tcp.seq() != nextSeq)
        {
            buffMap.put(tcp.seq(), new PacketData(ip4, tcp));
            throw new StopException();
        }
        else
        {
            doTcp(ip4, tcp, timestamp);
            nextSeq += tcp.getPayloadLength();
            while (buffMap.size() > 0)
            {
                PacketData data = buffMap.remove(nextSeq);
                if (data != null)
                {
                    doTcp(data.ip4, data.tcp, data.timestamp);
                    nextSeq += data.length;
                }
                else
                {
                    break;
                }
            }
        }
    }

    protected void doTcp(Ip4 ip4, Tcp tcp, long timestamp)
    {

    }

}
