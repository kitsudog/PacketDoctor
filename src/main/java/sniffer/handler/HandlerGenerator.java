package sniffer.handler;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

import sniffer.DisconnectException;
import sniffer.GiveupException;
import sniffer.filter.IFilter;
import sniffer.uitls.IpUtils;
import sniffer.view.IView;

public class HandlerGenerator implements PcapPacketHandler<String>
{

    private Class<? extends PacketHandler> handlerClass;

    private HashMap<Long, PacketHandler> pool = new HashMap<Long, PacketHandler>();

    private IView view;

    private List<IFilter> filters;

    private int source;

    public HandlerGenerator(Class<? extends PacketHandler> handlerClass, IView view)
    {
        this.handlerClass = handlerClass;
        this.view = view;
        this.filters = new ArrayList<IFilter>();
    }

    public void setSource(int ip)
    {
        source = ip;
    }

    public void nextPacket(int frameNum, Ip4 ip4, Tcp tcp)
    {
        if (tcp == null || ip4 == null)
        {
            return;
        }
        for (IFilter filter : filters)
        {
            if (!filter.doFilter(ip4, tcp))
            {
                // 被屏蔽了
                return;
            }
        }
        try
        {
            PacketHandler handler = getHandler(ip4, tcp);
            if (ip4.sourceToInt() == source)
            {
                handler.sendPacket(frameNum, ip4, tcp, tcp.getPacket().getCaptureHeader().timestampInMillis());
            }
            else if (ip4.destinationToInt() == source)
            {
                handler.recvPacket(frameNum, ip4, tcp, tcp.getPacket().getCaptureHeader().timestampInMillis());
            }
        }
        catch (GiveupException e)
        {
            dump("无法识别的中间态的链接", frameNum, ip4.getPacket());
            removeHandler(ip4, tcp);
        }
        catch (DisconnectException e)
        {
            view.info(String.format("断开一个连接 %s", ip4.sourceToInt() == source ? IpUtils.toServerDesc(ip4, tcp) : IpUtils.fromClientDesc(ip4, tcp)));
        }
        catch (Exception e)
        {
            dump("解析出现异常", frameNum, tcp.getPacket());
            e.printStackTrace();
            removeHandler(ip4, tcp);
        }
    }

    private void dump(String msg, int frameNum, JPacket packet)
    {
        Ip4 ip4 = packet.getHeader(new Ip4());
        Tcp tcp = packet.getHeader(new Tcp());
        int source = 0;
        int sourcePort = 0;
        int destination = 0;
        int destinationPort = 0;
        if (ip4.sourceToInt() == this.source)
        {
            source = ip4.sourceToInt();
            sourcePort = tcp.source();
            destination = ip4.destinationToInt();
            destinationPort = tcp.destination();
        }
        else if (ip4.destinationToInt() == this.source)
        {
            source = ip4.destinationToInt();
            sourcePort = tcp.destination();
            destination = ip4.sourceToInt();
            destinationPort = tcp.source();
        }
        view.error(msg
                + "\n"
                + String.format("frame: %d\t%s:%d => %s:%d\n", frameNum, IpUtils.int2string(source), sourcePort, IpUtils.int2string(destination),
                        destinationPort)//
                + String.format("tcp.port == %d && tcp.port == %d && ip.host == %s\n", sourcePort, destinationPort, IpUtils.int2string(destination))//
                + packet.toHexdump());
    }

    private int cnt = 1;

    @Override
    public void nextPacket(PcapPacket packet, String user)
    {
        Ip4 ip4 = packet.getHeader(new Ip4());
        Tcp tcp = packet.getHeader(new Tcp());
        nextPacket(cnt++, ip4, tcp);
    }

    private void removeHandler(Ip4 ip4, Tcp tcp)
    {
        int destinationHost;
        int sourcePort;
        int destinationPort;
        if (ip4.sourceToInt() == source)
        {
            destinationHost = ip4.destinationToInt();
            sourcePort = tcp.source();
            destinationPort = tcp.destination();
        }
        else if (ip4.destinationToInt() == source)
        {
            destinationHost = ip4.sourceToInt();
            sourcePort = tcp.destination();
            destinationPort = tcp.source();
        }
        else
        {
            throw new RuntimeException("不能定位的");
        }
        long key = ((long) destinationHost << 32) | (sourcePort << 16) | destinationPort;
        pool.remove(key);
    }

    private PacketHandler getHandler(Ip4 ip4, Tcp tcp)
    {
        int sourceHost;
        int destinationHost;
        int sourcePort;
        int destinationPort;
        if (ip4.sourceToInt() == source)
        {
            sourceHost = ip4.sourceToInt();
            destinationHost = ip4.destinationToInt();
            sourcePort = tcp.source();
            destinationPort = tcp.destination();
        }
        else if (ip4.destinationToInt() == source)
        {
            sourceHost = ip4.destinationToInt();
            destinationHost = ip4.sourceToInt();
            sourcePort = tcp.destination();
            destinationPort = tcp.source();
        }
        else
        {
            throw new RuntimeException("不能定位的");
        }
        long key = ((long) destinationHost << 32) | (sourcePort << 16) | destinationPort;
        PacketHandler handler = pool.get(key);
        if (handler == null)
        {
            try
            {
                handler = handlerClass.newInstance();
                handler.setView(view);
                handler.setInfo(sourceHost, sourcePort, destinationHost, destinationPort);
                pool.put(key, handler);
            }
            catch (InstantiationException e)
            {
                e.printStackTrace();
            }
            catch (IllegalAccessException e)
            {
                e.printStackTrace();
            }
        }
        return handler;
    }

    public void addFilter(IFilter filter)
    {
        filters.add(filter);
    }

}
