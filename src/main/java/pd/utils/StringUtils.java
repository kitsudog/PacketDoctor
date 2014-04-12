package pd.utils;

import java.util.LinkedList;
import java.util.List;

public class StringUtils
{

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
