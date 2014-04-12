package pd.source;

import java.util.concurrent.LinkedBlockingQueue;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

public class LibPcapSource implements ISource
{
    class Handler implements PcapPacketHandler<String>
    {

        private LinkedBlockingQueue<PcapPacket> queue;

        public Handler(LinkedBlockingQueue<PcapPacket> queue)
        {
            this.queue = queue;
        }

        @Override
        public void nextPacket(PcapPacket packet, String user)
        {
            queue.add(packet);
        }

    }

    private Pcap pcap;

    private PcapIf device;

    private Handler handler;

    private LinkedBlockingQueue<PcapPacket> packetQueue;

    private int skip;

    public LibPcapSource(PcapIf device)
    {
        packetQueue = new LinkedBlockingQueue<PcapPacket>();
        handler = new Handler(packetQueue);
        this.device = device;
    }

    @Override
    public JPacket next()
    {
        if (skip > 0)
        {
            while (packetQueue.isEmpty())
            {
                try
                {
                    Thread.sleep(10);
                }
                catch (InterruptedException e)
                {
                    e.printStackTrace();
                }
            }
            packetQueue.poll();
            skip--;
        }
        while (packetQueue.isEmpty())
        {
            try
            {
                Thread.sleep(10);
            }
            catch (InterruptedException e)
            {
                e.printStackTrace();
            }
        }
        return packetQueue.poll();
    }

    @Override
    public void init()
    {
        int snaplen = 64 * 1024;
        int flags = Pcap.MODE_PROMISCUOUS;
        int timeout = 1 * 1000;
        StringBuilder errbuf = new StringBuilder();
        pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
        new Thread(new Runnable()
        {

            @Override
            public void run()
            {
                while (true)
                {
                    pcap.loop(1, handler, null);
                }
            }
        }).start();
    }

    @Override
    public void skip(int skip)
    {
        this.skip = skip;
    }

}
