package sniffer.uitls;

public class IpUtils
{
    public final static int bytes2int(byte[] ip)
    {
        return ((ip[0] & 0xff) << 24) | ((ip[1] & 0xff) << 16) | ((ip[2] & 0xff) << 8) | (ip[3] & 0xff);
    }

    public final static byte[] int2bytes(int ip)
    {
        byte result[] = new byte[4];
        result[0] = (byte) ((ip >> 24) & 0xff);
        result[1] = (byte) ((ip >> 16) & 0xff);
        result[2] = (byte) ((ip >> 8) & 0xff);
        result[3] = (byte) (ip & 0xff);
        return result;
    }

    public final static String int2string(int ip)
    {
        int result[] = new int[4];
        result[0] = ((ip >> 24) & 0xff);
        result[1] = ((ip >> 16) & 0xff);
        result[2] = ((ip >> 8) & 0xff);
        result[3] = (ip & 0xff);
        return String.format("%d.%d.%d.%d", result[0], result[1], result[2], result[3]);
    }

    public static int string2int(String ip)
    {
        return string2int(ip, true, 0xffffffff);
    }

    public static int string2int(String ip, int defaultIp)
    {
        return string2int(ip, false, defaultIp);
    }

    public static int string2int(String ip, boolean isAssert, int defaultIp) throws IllegalArgumentException
    {
        String[] tmp = ip.split("\\.");
        if (tmp.length != 4)
        {
            if (isAssert)
            {
                throw new IllegalArgumentException("不正确的ip地址");
            }
            else
            {
                return defaultIp;
            }
        }
        int result = 0;
        try
        {
            for (String t : tmp)
            {
                result <<= 8;
                int b = Integer.parseInt(t);
                if (b > 255 || b < 0)
                {
                    throw new Exception();
                }
                result |= b;
            }
        }
        catch (Exception e)
        {
            if (isAssert)
            {
                throw new IllegalArgumentException("不正确的ip地址");
            }
            else
            {
                return defaultIp;
            }
        }
        return result;
    }
}
