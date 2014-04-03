package sniffer.handler;

import java.util.HashMap;
import java.util.Map;

import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

import sniffer.GiveupException;
import sniffer.HandlerException;
import sniffer.StopException;
import sniffer.utils.Asserts;

public class TcpHandler extends AbstractPacketHandler
{

    enum STATE {
        UNKNOWN, CLOSED, LISTEN, SYN_SENT, SYNC_RCVD, ESTABLISHED, CLOSE_WAIT, LAST_ACK, FIN_WAIT_1, FIN_WAIT_2, TIME_WAIT, CLOSING;
        public STATE send(int flags)
        {
            throw new RuntimeException("未知的状态");
        }

        public STATE recv(int flags)
        {
            throw new RuntimeException("未知的状态");
        }
    }

    public boolean isServer = true;

    class PacketData
    {

        public PacketData(int frameId, Ip4 ip4, Tcp tcp, long timestamp)
        {
            this.frameId = frameId;
            this.ip4 = ip4;
            this.tcp = tcp;
            this.seq = tcp.seq();
            this.payload = tcp.getPayload();
            this.timestamp = timestamp;
            length = tcp.getPayloadLength();
        }

        byte[] payload;

        long frameId;

        long seq;

        Ip4 ip4;

        Tcp tcp;

        long timestamp;

        long length;
    }

    class TcpState
    {
        /**
         * 下一个发送序列
         */
        public long nextSeq = 0;

        /**
         * 已经接受的序列
         */
        public long ack = 0;

        public STATE state = STATE.CLOSED;

        public Map<Long, PacketData> recvBuff = new HashMap<Long, TcpHandler.PacketData>();

        public long lastAck;
    }

    private TcpState local = new TcpState();

    protected void sendTcp(Ip4 ip4, Tcp tcp, byte[] payload, long timestamp)
    {

    }

    protected void recvTcp(Ip4 ip4, Tcp tcp, byte[] payload, long timestamp)
    {

    }

    @Override
    final public void recvPacket(int frameId, Ip4 ip4, Tcp tcp, long timestamp) throws HandlerException
    {
        if (local.state == STATE.CLOSED)
        {
            // TODO: 当前为服务端的
        }
        else if (local.state == STATE.SYN_SENT)
        {
            Asserts.isTrue("不正常的状态", tcp.flags() == 0x012);// SYN,ACK
            Asserts.isEquals(tcp.ack() == local.nextSeq);
            local.ack = tcp.seq() + 1;
            local.state = STATE.SYNC_RCVD;
        }
        else if (local.state == STATE.ESTABLISHED)
        {
            if (tcp.flags() == 0x010 || tcp.flags() == 0x018)// ACK|ACK, PSH
            {
                if (tcp.seq() < local.ack)
                {
                    view.debug("Repeat: " + frameId);
                }
                else if (tcp.seq() > local.ack)
                {
                    view.debug("Out-of-order: " + frameId);
                    local.recvBuff.put(tcp.seq(), new PacketData(frameId, ip4, tcp, timestamp));
                }
                else
                {
                    local.recvBuff.put(tcp.seq(), new PacketData(frameId, ip4, tcp, timestamp));
                    while (local.recvBuff.size() > 0)
                    {
                        PacketData packet = local.recvBuff.remove(local.ack);
                        if (packet == null)
                        {
                            break;
                        }
                        local.ack = packet.tcp.seq() + packet.tcp.getPayloadLength();
                        recvTcp(packet.ip4, packet.tcp, packet.payload, packet.timestamp);
                    }
                }
            }
            else if (tcp.flags() == 0x011 || tcp.flags() == 0x019)// FIN,ACK|FIN,PSH,ACK
            {
                local.state = STATE.FIN_WAIT_1;
                local.lastAck = tcp.seq() + tcp.getPayloadLength() + 1;
            }
            else if (tcp.flags() == 0x010)// ACK
            {
                Asserts.isTrue("状态不正确", local.nextSeq == tcp.seq());
                local.state = STATE.CLOSED;
                throw new StopException();
            }
            else
            {
                throw new RuntimeException("状态不对");
            }
        }
        else if (local.state == STATE.CLOSE_WAIT)
        {
            if (tcp.flags() == 0x011 || tcp.flags() == 0x019)
            // FIN, ACK |FIN, PSH, ACK
            {
                Asserts.isTrue("状态不对", tcp.ack() == local.nextSeq);
                local.state = STATE.LAST_ACK;
                local.lastAck = tcp.seq() + tcp.getPayloadLength() + 1;
            }
            else
            {
                // 只能是单纯的确认了
                Asserts.isTrue("状态不对", tcp.flags() == 0x010); // ACK
            }
        }
        else if (local.state == STATE.FIN_WAIT_2)
        {
            // TODO: 这里的校验还没做
            // Asserts.isTrue("状态不对", tcp.ack() == local.lastAck);
            local.state = STATE.CLOSED;
        }
        else
        {
            throw new RuntimeException("状态不对");
        }
    }

    @Override
    final public void sendPacket(int frameId, Ip4 ip4, Tcp tcp, long timestamp) throws HandlerException
    {
        if (local.nextSeq > tcp.seq() && local.state != STATE.CLOSED)
        {
            view.debug("Retransmission: " + frameId);
            return;
        }
        if (local.state == STATE.CLOSED)
        {
            if (tcp.flags() == 0x002)// SYN
            {
                Asserts.isTrue(tcp.ack() == 0);
                // 发起握手协议
                local.nextSeq = tcp.seq() + 1;
                local.state = STATE.SYN_SENT;
            }
            else
            {
                throw new GiveupException();
            }
        }
        else if (local.state == STATE.SYNC_RCVD)
        {
            Asserts.isTrue("不正常的状态", tcp.flags() == 0x010);// ACK
            Asserts.isTrue(local.ack == tcp.ack());
            Asserts.isTrue(tcp.getPayloadLength() == 0);
            local.state = STATE.ESTABLISHED;
        }
        else if (local.state == STATE.ESTABLISHED)
        {
            if (tcp.flags() == 0x010 || tcp.flags() == 0x018)// ACK|ACK, PSH
            {
                // 发送数据以及确认
                if (tcp.seq() < local.nextSeq)
                {
                    view.debug("Retransmission: " + frameId);
                }
                else
                {
                    local.nextSeq = tcp.seq() + tcp.getPayloadLength();
                    local.ack = tcp.ack();
                    sendTcp(ip4, tcp, tcp.getPayload(), timestamp);
                }
            }
            else if (tcp.flags() == 0x011)// FIN, ACK
            {
                local.state = STATE.CLOSE_WAIT;
                local.nextSeq = tcp.seq() + 1;
            }
            else
            {
                throw new RuntimeException("状态不对");
            }
        }
        else if (local.state == STATE.FIN_WAIT_1)
        {
            // 此后应该不在发送任何数据了(只有确认包)
            Asserts.isTrue("状态不对", tcp.flags() == 0x010);// ACK
            Asserts.isTrue("状态不对", tcp.seq() == local.nextSeq);
            if (tcp.ack() == local.lastAck)
            {
                local.state = STATE.FIN_WAIT_2;
                // local.lastAck = tcp.seq() + 1;
            }
            else
            {
                // 单纯的发送数据确认而已
            }
        }
        else if (local.state == STATE.FIN_WAIT_2)
        {
            Asserts.isTrue("状态不对", tcp.flags() == 0x011);// FIN, ACK
            Asserts.isTrue("状态不对", tcp.ack() == local.lastAck);
        }
        else if (local.state == STATE.CLOSE_WAIT)
        {
            // 不应该有任何发送了
            // TODO:重传应该被处理
            throw new RuntimeException("状态不对");
        }
        else if (local.state == STATE.LAST_ACK)
        {
            Asserts.isTrue("状态不对", tcp.ack() == local.lastAck);
        }
        else
        {
            // 未知的状态
            throw new RuntimeException("状态不对");
        }
    }
}
