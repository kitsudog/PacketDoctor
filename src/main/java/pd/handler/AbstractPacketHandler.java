package pd.handler;

import pd.view.IView;

public abstract class AbstractPacketHandler implements PacketHandler
{

    protected IView view;

    public int sourceHost;

    public int sourcePort;

    public int destinationHost;

    public int destinationPort;

    @Override
    public void setView(IView view)
    {
        this.view = view;
    }

    @Override
    public void setInfo(int sourceHost, int sourcePort, int destinationHost, int destinationPort)
    {
        this.sourceHost = sourceHost;
        this.sourcePort = sourcePort;
        this.destinationHost = destinationHost;
        this.destinationPort = destinationPort;

    }
}
