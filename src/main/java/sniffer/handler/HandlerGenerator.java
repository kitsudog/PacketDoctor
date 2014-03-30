package sniffer.handler;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

import sniffer.GiveupException;
import sniffer.StopException;
import sniffer.filter.IFilter;
import sniffer.view.IView;

public class HandlerGenerator implements PcapPacketHandler<String>
{

    private Class<? extends PacketHandler> handlerClass;

    private HashMap<String, PacketHandler> pool = new HashMap<String, PacketHandler>();

    private IView view;

    private List<IFilter> filters;

    public HandlerGenerator(Class<? extends PacketHandler> handlerClass, IView view)
    {
        this.handlerClass = handlerClass;
        this.view = view;
        this.filters = new ArrayList<IFilter>();
    }

    public void nextPacket(Ip4 ip4, Tcp tcp)
    {
        if (tcp == null || ip4 == null)
        {
            return;
        }
        try
        {
            getHandler(ip4, tcp).nextPacket(ip4, tcp, tcp.getPacket().getCaptureHeader().timestampInMillis());
        }
        catch (GiveupException e)
        {
            removeHandler(ip4, tcp);
        }
        catch (StopException e)
        {
            // Pass
        }
        catch (Exception e)
        {
            removeHandler(ip4, tcp);
            e.printStackTrace();
        }
    }

    @Override
    public void nextPacket(PcapPacket packet, String user)
    {
        Ip4 ip4 = packet.getHeader(new Ip4());
        Tcp tcp = packet.getHeader(new Tcp());
        if (tcp == null)
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
        nextPacket(ip4, tcp);
    }

    private void removeHandler(Ip4 ip4, Tcp tcp)
    {
        int sourceHost = ip4.sourceToInt();
        int destinationHost = ip4.destinationToInt();
        int sourcePort = tcp.source();
        int destinationPort = tcp.destination();
        String sourceKey = String.format("%d:%d", sourceHost, sourcePort);
        String destinationKey = String.format("%d:%d", destinationHost, destinationPort);
        pool.remove(sourceKey + "=>" + destinationKey);
        pool.remove(destinationKey + "=>" + sourceKey);
    }

    private PacketHandler getHandler(Ip4 ip4, Tcp tcp)
    {
        int sourceHost = ip4.sourceToInt();
        int destinationHost = ip4.destinationToInt();
        int sourcePort = tcp.source();
        int destinationPort = tcp.destination();
        String sourceKey = String.format("%d:%d", sourceHost, sourcePort);
        String destinationKey = String.format("%d:%d", destinationHost, destinationPort);
        PacketHandler handler = pool.get(sourceKey + "=>" + destinationKey);
        if (handler == null)
        {
            handler = pool.get(destinationKey + "=>" + sourceKey);
            if (handler == null)
            {
                try
                {
                    handler = handlerClass.newInstance();
                    handler.setView(view);
                    pool.put(sourceKey + "=>" + destinationKey, handler);
                    pool.put(destinationKey + "=>" + sourceKey, handler);
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
        }
        return handler;
    }

    public void addFilter(IFilter filter)
    {
        filters.add(filter);
    }

}
