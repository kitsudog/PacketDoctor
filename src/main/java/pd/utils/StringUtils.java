package pd.utils;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

public class StringUtils
{

    public static String toHex(byte[] data)
    {
        StringBuilder sb = new StringBuilder();
        int i = 0;
        for (byte b : data)
        {
            sb.append(String.format("%02X ", (b & 0xff)));
            if (i++ == 16)
            {
                i = 0;
                sb.append("\n");
            }
        }
        return sb.toString();
    }

    public static List<String> toHexList(byte[] data)
    {
        ArrayList<String> result = new ArrayList<String>();
        StringBuilder sb = new StringBuilder();
        int i = 0;
        for (byte b : data)
        {
            sb.append(String.format("%02X ", (b & 0xff)));
            if (i++ == 16)
            {
                result.add(sb.toString());
                i = 0;
                sb = new StringBuilder();
            }
        }
        if (sb.length() > 0)
        {
            result.add(sb.toString());
        }
        return result;
    }

    public static String justify(String str)
    {
        String[] lines = str.split("\n");
        List<Integer> cols = new LinkedList<Integer>();
        for (String line : lines)
        {
            int i = 0;
            for (String u : line.split("\t+"))
            {
                if (cols.size() > i)
                {
                    cols.set(i, Math.max(cols.get(i), u.length()));
                }
                else
                {
                    cols.add(u.length());
                }
                i++;
            }
        }
        StringBuilder result = new StringBuilder();
        for (String line : lines)
        {
            int i = 0;
            for (String u : line.split("\t+"))
            {
                result.append(String.format("%-" + cols.get(i) + "s    ", u));
                i++;
            }
            result.append("\n");
        }
        return result.toString();
    }
}
