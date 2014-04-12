package pd.source;

import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Arrays;

import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.JPacket;

import pd.utils.PCAPFileReader;

public class ProcessSource implements ISource
{

    private String command;

    private File tempFile;

    private Process subproc;

    private PCAPFileReader reader;

    private int type;

    public ProcessSource(String command)
    {
        this.command = command;
    }

    @Override
    public void init()
    {
        try
        {
            tempFile = File.createTempFile("dump", ".pcap");
            String command = this.command.replaceAll("\\{\\}", tempFile.getPath().replaceAll("\\\\", "/"));
            subproc = Runtime.getRuntime().exec(command);
            Runtime.getRuntime().addShutdownHook(new Thread(new Runnable()
            {
                @Override
                public void run()
                {
                    subproc.destroy();
                    tempFile.delete();
                    subproc.destroy();
                }
            }));
            reader = new PCAPFileReader(new FileInputStream(tempFile));
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
        while (true)
        {
            try
            {
                if (reader.hasNext())
                {
                    byte[] buffer = reader.next();
                    JMemoryPacket packet = new JMemoryPacket(type, Arrays.copyOfRange(buffer, 16, buffer.length));
                    return packet;
                }
                else
                {
                    Thread.sleep(10);
                }
            }
            catch (InterruptedException e)
            {
                e.printStackTrace();
            }
            catch (EOFException e)
            {
                // PASS
            }
            catch (Exception e)
            {
                e.printStackTrace();
            }
        }
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
