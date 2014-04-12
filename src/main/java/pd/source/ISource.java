package pd.source;

import java.io.EOFException;

import org.jnetpcap.packet.JPacket;

public interface ISource
{
    void init();

    JPacket next() throws EOFException;

    void skip(int skip);
}
