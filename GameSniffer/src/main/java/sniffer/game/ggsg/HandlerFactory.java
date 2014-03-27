package sniffer.game.ggsg;

import java.util.HashMap;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

import sniffer.IOut;
import sniffer.PacketHandler;

public class HandlerFactory implements PcapPacketHandler<String> {

	private Class<? extends PacketHandler> handlerClass;
	private HashMap<String, PacketHandler> pool = new HashMap<String, PacketHandler>();
	private IOut out;

	public HandlerFactory(Class<? extends PacketHandler> handlerClass, IOut out) {
		this.handlerClass = handlerClass;
		this.out = out;
	}

	@Override
	public void nextPacket(PcapPacket packet, String user) {
		Ip4 ip4 = packet.getHeader(new Ip4());
		Tcp tcp = packet.getHeader(new Tcp());
		if (tcp == null) {
			return;
		}
		long time = packet.getCaptureHeader().timestampInMillis();
		try {
			getHandler(ip4, tcp).nextPacket(ip4, tcp, time);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public PacketHandler getHandler(Ip4 ip4, Tcp tcp) {
		byte[] sourceHost = ip4.source();
		byte[] destinationHost = ip4.destination();
		int sourcePort = tcp.source();
		int destinationPort = tcp.destination();
		String sourceKey = String.format("%d.%d.%d.%d:%d", sourceHost[0],
				sourceHost[1], sourceHost[2], sourceHost[3], sourcePort);
		String destinationKey = String.format("%d.%d.%d.%d:%d",
				destinationHost[0], destinationHost[1], destinationHost[2],
				destinationHost[3], destinationPort);
		PacketHandler handler = pool.get(sourceKey + "=>" + destinationKey);
		if (handler == null) {
			handler = pool.get(destinationKey + "=>" + sourceKey);
			if (handler == null) {
				try {
					handler = handlerClass.newInstance();
					handler.setOut(out);
					pool.put(sourceKey + "=>" + destinationKey, handler);
					pool.put(destinationKey + "=>" + sourceKey, handler);
				} catch (InstantiationException e) {
					e.printStackTrace();
				} catch (IllegalAccessException e) {
					e.printStackTrace();
				}
			}
		}
		return handler;
	}
}
