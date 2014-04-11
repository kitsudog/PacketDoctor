package pd.utils;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

@SuppressWarnings("unused")
public class PCAPFileReader
{
    public static final int BUFF_SIZE = 102400;

    private InputStream is;

    private ByteBuffer buff = ByteBuffer.allocate(BUFF_SIZE);

    private short version_major;

    private short version_minor;

    private int thiszone;

    private int sigfigs;

    private int snaplen;

    private int linktype;

    public PCAPFileReader(InputStream is) throws IOException
    {
        this.is = is;
        byte[] b = new byte[24];
        is.read(b);
        ByteBuffer temp = ByteBuffer.wrap(b);
        temp.order(ByteOrder.BIG_ENDIAN);
        int magic = temp.getInt();
        if (magic == 0xa1b2c3d4)
        {
            buff.order(ByteOrder.BIG_ENDIAN);
        }
        if (magic == 0xd4c3b2a1)
        {
            buff.order(ByteOrder.LITTLE_ENDIAN);
        }
        else
        {
            throw new Error("不支持的文件类型");
        }
        version_major = temp.getShort();
        version_minor = temp.getShort();
        thiszone = temp.getInt();
        sigfigs = temp.getInt();
        snaplen = temp.getInt();
        linktype = temp.getInt();
        buff.flip();
    }

    synchronized public boolean hasNext() throws IOException
    {
        if (is == null)
        {
            throw new Error("已经关闭不能读取了");
        }
        return buff.remaining() > 0 || is.available() > 0;
    }

    synchronized public byte[] next() throws IOException
    {
        if (is == null)
        {
            throw new Error("已经关闭不能读取了");
        }
        do
        {
            byte[] result = decodeOne();
            if (result != null)
            {
                return result;
            }
            byte[] b = new byte[4096];
            int cnt = is.read(b);
            if (cnt < 0)
            {
                throw new EOFException();
            }
            buff.compact();
            buff.put(b, 0, cnt);
            buff.flip();
        }
        while (true);
    }

    synchronized public void skip(int num) throws IOException
    {
        if (is == null)
        {
            throw new Error("已经关闭不能读取了");
        }
        while (num-- > 0)
        {
            next();
        }
    }

    private byte[] decodeOne()
    {
        if (buff.remaining() < 16)
        {
            return null;
        }
        buff.mark();
        // pcap_pkthdr
        buff.getLong();
        int caplen = buff.getInt();
        int len = buff.getInt();
        if (len != caplen || len <= 0)
        {
            buff.reset();
            byte[] dst = new byte[buff.remaining()];
            buff.get(dst);
            int cnt = 0;
            for (byte b : dst)
            {
                System.err.print(String.format("%02x ", b));
                cnt++;
                if (cnt % 16 == 0)
                {
                    System.err.println();
                }
                else if (cnt % 8 == 0)
                {
                    System.err.print("  ");
                }
            }
            System.err.println();
            throw new Error("错误的帧");
        }
        if (buff.remaining() < caplen)
        {
            buff.reset();
            return null;
        }
        byte[] result = new byte[16 + caplen];
        buff.reset();
        buff.get(result);
        return result;
    }

    synchronized public void clsoe() throws IOException
    {
        is.close();
        is = null;
    }

}
