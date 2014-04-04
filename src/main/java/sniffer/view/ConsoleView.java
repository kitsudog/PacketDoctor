package sniffer.view;

import java.io.BufferedReader;
import java.io.InputStreamReader;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;

public class ConsoleView implements IView
{

    private boolean debug;

    @Override
    public void info(String msg)
    {
        if (!debug)
        {
            System.out.println(msg);
        }
    }

    @Override
    public void addNode(MessageData data)
    {
        StringBuilder sb = new StringBuilder();
        sb.append(data.title + "\n");
        if (data.content != null)
        {
            sb.append(parse(data.content, "   +"));
        }
        System.out.println(sb.toString());
    }

    private String parse(JSONObject content, String prefix)
    {
        StringBuilder sb = new StringBuilder();
        int len = 0;
        for (Object key : content.keySet())
        {
            if (key.toString().length() > len)
            {
                len = key.toString().length();
            }
        }
        len = (int) (Math.pow(4, Math.ceil(Math.log(len) / Math.log(4))) + 3);
        String fmt = String.format("%s%%-%ds:%%s\n", prefix, len);
        for (Object key : content.keySet())
        {
            Object value = content.get(key);
            if (value instanceof JSONObject)
            {
                sb.append(String.format(fmt, key, "{...}"));
                sb.append(parse((JSONObject) value, prefix + "   +"));
            }
            else if (value instanceof JSONArray)
            {
                sb.append(String.format(fmt, key, "[...]"));
                sb.append(parse((JSONArray) value, prefix + "   +"));
            }
            else
            {
                sb.append(String.format(fmt, key, value.toString().replaceAll("\\r|\\n", "\\\\n")));
            }
        }
        return sb.toString();
    }

    private String parse(JSONArray content, String prefix)
    {
        StringBuilder sb = new StringBuilder();
        int len = (int) Math.round(Math.log10(content.size()));
        len = (int) (Math.pow(4, Math.ceil(Math.log(len) / Math.log(4))) + 3);
        String fmt = String.format("%s%%-%d%s:%%s\n", prefix, len);
        for (int i = 0; i < content.size(); i++)
        {
            Object value = content.get(i);
            if (value instanceof JSONObject)
            {
                sb.append(String.format(fmt, i, "{...}"));
                sb.append(parse((JSONObject) value, prefix + "   +"));
            }
            else if (value instanceof JSONArray)
            {
                sb.append(String.format(fmt, i, "[...]"));
                sb.append(parse((JSONArray) value, prefix + "   +"));
            }
            else
            {
                sb.append(String.format(fmt, i, value));
            }
        }
        return sb.toString();
    }

    @Override
    public void alert(String msg)
    {
        System.err.println(msg);
    }

    public void debug(String msg)
    {
        if (debug)
        {
            System.err.println(msg);
        }
    }

    @Override
    public void error(String msg)
    {
        for (String str : msg.split("\n"))
        {
            System.err.println("[ERROR] " + str);
        }
    }

    @Override
    public String input(String msg, String defaultText)
    {
        System.out.println(String.format("%s:[%s]", msg, defaultText));
        try
        {
            InputStreamReader reader = new InputStreamReader(System.in);
            BufferedReader br = new BufferedReader(reader);
            String line = br.readLine();
            br.close();
            reader.close();
            return line == null ? defaultText : line;
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
        return defaultText;
    }

    @Override
    public int confirm(String msg, String options[])
    {
        InputStreamReader reader = new InputStreamReader(System.in);
        BufferedReader br = new BufferedReader(reader);
        while (true)
        {
            System.out.println(String.format("%s:", msg));
            for (int i = 0; i < options.length; i++)
            {
                System.out.println(String.format("%d:%s", i, options[i]));
            }
            try
            {
                String line = br.readLine();
                for (int i = 0; i < options.length; i++)
                {
                    if (options[i].equals(line))
                    {
                        return i;
                    }
                }
                int i = Integer.parseInt(line);
                if (i >= 0 && i < options.length)
                {
                    return i;
                }
            }
            catch (Exception e)
            {
                e.printStackTrace();
            }
            System.err.println("请重新输入");
        }
    }

    public void setDebug(boolean debug)
    {
        this.debug = debug;
    }

}
