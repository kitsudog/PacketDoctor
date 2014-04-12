package pd.source;

import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.util.Arrays;

import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.JPacket;

import pd.utils.EndlessFileInputStream;
import pd.utils.PCAPFileReader;

public class FileSource implements ISource
{

    private File file;

    private PCAPFileReader reader;

    private int type;

    public FileSource(String file)
    {
        this.file = new File(file);
    }

    @Override
    public void init()
    {
        try
        {
            reader = new PCAPFileReader(new EndlessFileInputStream(file));
            type = reader.getLinktype();
            if (type == -1)
            {
                throw new RuntimeException("不支持的格式");
            }
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }

    @Override
    public JPacket next() throws EOFException
    {
        try
        {
            if (!reader.hasNext())
            {
                throw new EOFException();
            }
            byte[] buffer = reader.next();
            JMemoryPacket packet = new JMemoryPacket(type, Arrays.copyOfRange(buffer, 16, buffer.length));
            return packet;
        }
        catch (EOFException e)
        {
            throw e;
        }
        catch (IOException e)
        {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public void skip(int skip)
    {
        try
        {
            reader.skip(skip);
        }
        catch (IOException e)
        {
            e.printStackTrace();
        }
    }

}
