package sniffer.game.ggsg;

import sniffer.IOut;
import sniffer.PacketHandler;

public abstract class AbstractPacketHandler implements PacketHandler {

	protected IOut out;

	@Override
	public void setOut(IOut out) {
		this.out = out;
	}

}
