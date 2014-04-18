package pd.handler;

import java.util.HashMap;
import java.util.Map;

import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Tcp.Flag;

import pd.exception.DisconnectException;
import pd.exception.HandlerException;
import pd.utils.Asserts;
import pd.utils.IpUtils;

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

        public PacketData(int frameNum, Ip4 ip4, Tcp tcp, long timestamp)
        {
            this.frameNum = frameNum;
            this.ip4 = ip4;
            this.tcp = tcp;
            this.seq = tcp.seq();
            // PATCH: 此处必须保留一份否则滞后再调用会导致lib中的代码出现异常
            this.payload = tcp.getPayload();
            this.timestamp = timestamp;
            length = tcp.getPayloadLength();
        }

        byte[] payload;

        long frameNum;

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

        public long win;

        /**
         * 基于窗口计算的最大序列值
         */
        public long maxSeq;
    }

    private final TcpState local = new TcpState();

    protected void sendTcp(Ip4 ip4, Tcp tcp, byte[] payload, long timestamp)
    {

    }

    protected void recvTcp(Ip4 ip4, Tcp tcp, byte[] payload, long timestamp)
    {

    }

    @Override
    final public void recvPacket(int frameNum, Ip4 ip4, Tcp tcp, long timestamp) throws HandlerException
    {
        if (tcp.flags_RST())
        {
            // 当作是关闭处理了
            throw new DisconnectException("链接被重置了");
        }
        if (local.state == STATE.CLOSED || local.state == STATE.LISTEN) // Server
        {
            if (tcp.flags() == 0x002)
            // SYN
            {
                // 明确为服务端
                local.state = STATE.LISTEN;
                local.ack = tcp.seq();
            }
            else
            {
                // 默认处理为ESTABLISHED
                local.state = STATE.ESTABLISHED;
                local.ack = tcp.seq();
                local.nextSeq = tcp.ack();
            }
        }
        else if (local.state == STATE.SYNC_RCVD) // Server
        {
            if (tcp.flags() == 0x040) // RST
            {
                local.state = STATE.LISTEN;
            }
            else if (tcp.flags() == 0x010) // ACK
            {
                Asserts.isTrue("握手第三步", tcp.ack() == local.nextSeq);
                local.state = STATE.ESTABLISHED;
            }
            else
            {
                throw new RuntimeException("未知的状态");
            }
        }
        else if (local.state == STATE.SYN_SENT) // Client
        {
            Asserts.isTrue("不正常的状态", tcp.flags() == 0x012);// SYN, ACK
            Asserts.isEquals(tcp.ack() == local.nextSeq);
            local.ack = tcp.seq() + 1;
        }
        else if (local.state == STATE.ESTABLISHED)
        {
            if (tcp.seq() < local.ack)
            {
                view.debug("Repeat: " + frameNum);
            }
            else if (tcp.flags() == 0x010 || tcp.flags() == 0x018)
            // ACK|ACK, PSH
            {
                if (tcp.seq() > local.ack)
                {
                    // TODO: 考虑窗口的因素来确认是包丢失还是乱序
                    view.debug("Out-of-order: " + frameNum);
                    local.recvBuff.put(tcp.seq(), new PacketData(frameNum, ip4, tcp, timestamp));
                }
                else
                {
                    local.recvBuff.put(tcp.seq(), new PacketData(frameNum, ip4, tcp, timestamp));
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
            else if (tcp.flags() == 0x011 || tcp.flags() == 0x019)
            // FIN,ACK|FIN, PSH, ACK
            {
                local.state = STATE.CLOSE_WAIT;
                local.ack = tcp.seq() + tcp.getPayloadLength() + 1;
                local.lastAck = local.ack;
            }
            else if (tcp.flags() == 0x010)
            // ACK
            {
                // TODO: 滑动窗口的判断
            }
            else
            {
                throw new RuntimeException("状态不对");
            }
        }
        else if (local.state == STATE.FIN_WAIT_1)// Client
        {
            if (tcp.flags_FIN())
            {
                // 等待发送 ACK
            }
            else
            {
                if (tcp.ack() == local.nextSeq)
                {
                    local.state = STATE.FIN_WAIT_2;
                }
                else
                {
                    // 单纯的确认之前的包而已
                }
            }
        }
        else if (local.state == STATE.FIN_WAIT_2)// Client
        {
            Asserts.isTrue("ack状态不对", tcp.ack() == local.nextSeq);
            if (tcp.flags() == 0x011 || tcp.flags() == 0x019)
            {
                // FIN, ACK |FIN, PSH, ACK
                local.state = STATE.TIME_WAIT;
                // sleep 什么的就算了
                local.state = STATE.CLOSED;
                throw new DisconnectException("主动断线");
            }
            else if (tcp.flags() == 0x010)
            {
                view.debug("Repeat: " + frameNum);
            }
        }
        else if (local.state == STATE.LAST_ACK)
        {
            Asserts.isTrue("断线前最后的包了", tcp.flags() == 0x010);// ACK
            local.state = STATE.CLOSED;
            throw new DisconnectException("完成断线请求");
        }
        else if (local.state == STATE.CLOSE_WAIT)
        {
            view.debug("ErrorPack: " + frameNum);
        }
        else
        {
            if (tcp.seq() < local.ack)
            {
                view.debug("Repeat: " + frameNum);
            }
            else
            {
                throw new RuntimeException("状态不对: " + local.state.name() + " recv " + Flag.toCompactString(tcp.flags()));
            }
        }
    }

    @Override
    final public void sendPacket(int frameId, Ip4 ip4, Tcp tcp, long timestamp) throws HandlerException
    {
        if (tcp.flags_RST())
        {
            // 当作是关闭处理了
            throw new DisconnectException("链接要重置了");
        }
        if (local.nextSeq > tcp.seq() && local.state != STATE.CLOSED)
        {
            // TODO: 滑动窗口
            view.debug("Retransmission: " + frameId);
            return;
        }
        if (local.state == STATE.LISTEN) // Server
        {
            Asserts.isTrue("发送握手包SYN, ACK", tcp.flags() == 0x012); // SYN, ACK
            local.state = STATE.SYNC_RCVD;
            local.nextSeq = tcp.seq() + 1;
            local.ack = tcp.ack();
        }
        else if (local.state == STATE.CLOSED) // Client
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
                // 默认当前状态为Establish的
                view.debug(String.format("发现一个已经存在的链接 %s", IpUtils.toServerDesc(ip4, tcp)));
                local.state = STATE.ESTABLISHED;
                local.nextSeq = tcp.seq() + tcp.getPayloadLength();
                local.ack = tcp.ack();
            }
        }
        else if (local.state == STATE.SYN_SENT) // Client
        {
            Asserts.isTrue("不正常的状态", tcp.flags() == 0x010);// ACK
            Asserts.isTrue(local.ack == tcp.ack());
            Asserts.isTrue(tcp.getPayloadLength() == 0);
            local.state = STATE.ESTABLISHED;
        }
        else if (local.state == STATE.ESTABLISHED) // Client
        {
            if (tcp.seq() < local.nextSeq)
            {
                view.debug("Retransmission: " + frameId);
            }
            else if (tcp.flags() == 0x010 || tcp.flags() == 0x018)
            // ACK | ACK, PSH
            {
                local.nextSeq = tcp.seq() + tcp.getPayloadLength();
                local.ack = tcp.ack();
                sendTcp(ip4, tcp, tcp.getPayload(), timestamp);
            }
            else if (tcp.flags() == 0x011 || tcp.flags() == 0x001)
            // FIN, ACK | FIN
            {
                local.state = STATE.FIN_WAIT_1;
                local.nextSeq = tcp.seq();
            }
            else
            {
                throw new RuntimeException("状态不对");
            }
        }
        else if (local.state == STATE.FIN_WAIT_1)
        {
            Asserts.isTrue("状态不对", tcp.flags() == 0x010);// ACK
            local.state = STATE.TIME_WAIT;
            // sleep 什么的就算了
            local.state = STATE.CLOSED;
            throw new DisconnectException("主动断线");
        }
        else if (local.state == STATE.TIME_WAIT)
        {
            Asserts.isTrue("状态不对", tcp.ack() == local.lastAck);
        }
        else if (local.state == STATE.FIN_WAIT_2)
        {
            Asserts.isTrue("状态不对", tcp.flags() == 0x011);// FIN, ACK
            Asserts.isTrue("状态不对", tcp.ack() == local.lastAck);
        }
        else if (local.state == STATE.CLOSE_WAIT) // Server
        {
            Asserts.isTrue("断线前必须发ACK", tcp.flags_ACK());
            if (tcp.flags_FIN())
            {
                local.state = STATE.LAST_ACK;
            }
        }
        else
        {
            if (tcp.seq() <= local.nextSeq)
            {
                view.debug("Retransmission: " + frameId);
            }
            else
            {
                // 未知的状态
                throw new RuntimeException(String.format("状态不对: %s (%s)", local.state.name(), tcp.flags()));
            }
        }
    }
}
