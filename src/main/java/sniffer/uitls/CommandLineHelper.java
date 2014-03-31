package sniffer.uitls;

import java.io.File;
import java.net.Inet4Address;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.GnuParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.Parser;

/**
 * 命令行工具的基类
 * @author zhangming.luo 2013-8-13
 * @see
 * @since 1.0
 */
final public class CommandLineHelper
{
    public static final int OPTION_FILE_EXIST = 1 << 0;

    public static final int OPTION_DIR_EXIST = 1 << 1;

    public static final int OPTION_CAN_WRITE = 1 << 2;

    public static final int OPTION_INT = 1 << 3;

    public static final int OPTION_IP = 1 << 4;

    public static final int OPTION_HOST = 1 << 5;

    private Parser parser = new GnuParser();

    private Options options;

    private Map<String, String> defaultValues = new HashMap<String, String>();

    private String header;

    public CommandLineHelper(String header, Options options)
    {
        this.header = header;
        this.options = options;
    }

    public CommandLineHelper(String header, Options options, Map<String, String> defaultValues)
    {
        this.header = header;
        this.options = options;
        this.defaultValues = defaultValues;
    }

    public Map<String, String> parse(String[] args) throws Exception
    {
        try
        {
            Map<String, String> map = new HashMap<String, String>();
            map.putAll(defaultValues);
            // parse the command line arguments
            Properties defaultProperties = new Properties();
            defaultProperties.putAll(defaultValues);
            CommandLine line = parser.parse(options, args, defaultProperties);
            // check params
            for (Option option : line.getOptions())
            {
                map.put(option.getLongOpt(), option.getValue());
                Object type = option.getType();
                if (type == null || !(type instanceof Integer))
                {
                    continue;
                }
                Integer exopt = (Integer) type;
                if ((exopt & OPTION_FILE_EXIST) > 0)
                {
                    File file = new File(option.getValue());
                    if (file.exists() && file.isFile())
                    {

                    }
                    else
                    {
                        throw new Exception("文件不存在");
                    }
                }
                if ((exopt & OPTION_DIR_EXIST) > 0)
                {
                    File file = new File(option.getValue());
                    if (file.exists() && file.isDirectory())
                    {

                    }
                    else
                    {
                        throw new Exception("目录不存在");
                    }
                }
                if ((exopt & OPTION_CAN_WRITE) > 0)
                {
                    File file = new File(option.getValue());
                    if (file.canWrite())
                    {

                    }
                    else
                    {
                        throw new Exception("目标不可写");
                    }
                }
                if ((exopt & OPTION_INT) > 0)
                {
                    try
                    {
                        Integer.parseInt(option.getValue());
                    }
                    catch (NumberFormatException e)
                    {
                        throw new Exception("不是有效的数字");
                    }
                }
                if ((exopt & OPTION_IP) > 0)
                {
                    if (!isIp(option.getValue()))
                    {
                        throw new Exception("不是有效的ip");
                    }
                }
                if ((exopt & OPTION_HOST) > 0)
                {
                    try
                    {
                        Inet4Address.getByName(option.getValue());
                    }
                    catch (UnknownHostException e)
                    {
                        throw new Exception("不是有效的主机ip或域名");
                    }
                }
            }
            // inject params
            return map;
        }
        catch (Exception e)
        {
            showUsage();
            throw new Exception(e.getMessage());
        }
    }

    private void showUsage()
    {
        HelpFormatter formatter = new HelpFormatter();
        String usageMsg = getClass().getName();
        formatter.printHelp(usageMsg, this.header, options, null, false);
    }

    private boolean isIp(String ip)
    {
        return ip.matches("((?:(?:25[0-5]|2[0-4]\\d|((1\\d{2})|([1-9]?\\d)))\\.){3}(?:25[0-5]|2[0-4]\\d|((1\\d{2})|([1-9]?\\d))))");
    }
}
