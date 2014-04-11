package pd.filter;

import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

public interface IFilter
{

    boolean doFilter(Ip4 ip4, Tcp tcp);

}
