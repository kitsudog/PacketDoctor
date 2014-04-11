package pd.filter;

import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

public class BaseFilter implements IFilter
{

    private int host;

    private int port;

    private boolean needHost = false;

    private boolean needPort = false;

    @Override
    public boolean doFilter(Ip4 ip4, Tcp tcp)
    {
        if (needHost)
        {
            if (ip4.sourceToInt() != host && ip4.destinationToInt() != host)
            {
                return false;
            }
        }
        if (needPort)
        {
            if (tcp.source() != port && tcp.destination() != port)
            {
                return false;
            }
        }
        return true;
    }

    public int getHost()
    {
        return host;
    }

    public void setHost(int host)
    {
        needHost = true;
        this.host = host;
    }

    public int getPort()
    {
        return port;
    }

    public void setPort(int port)
    {
        needPort = true;
        this.port = port;
    }

}
