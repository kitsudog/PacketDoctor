package pd.utils;

import java.io.File;
import java.net.Inet4Address;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

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

    static public class ExOpt
    {
        private Integer exopt;

        private List<String> radioParamList = new LinkedList<String>();

        private List<String> partnerParamList = new LinkedList<String>();

        private ExOpt()
        {

        }

        public ExOpt exopt(Integer value)
        {
            this.exopt = value;
            return this;
        }

        public ExOpt radio(String... params)
        {
            for (String param : params)
            {
                radioParamList.add(param);
            }
            return this;
        }

        public ExOpt partner(String... params)
        {
            for (String param : params)
            {
                partnerParamList.add(param);
            }
            return this;
        }

        public static ExOpt newOne(Integer exopt)
        {
            ExOpt opt = new ExOpt();
            opt.exopt(exopt);
            return opt;
        }

        public static ExOpt newOne()
        {
            ExOpt opt = new ExOpt();
            return opt;
        }
    }

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

    public Map<String, String> parse(String[] args)
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
            Set<String> radioSet = new HashSet<String>();
            Set<String> partnerSet = new HashSet<String>();
            for (Option option : line.getOptions())
            {
                map.put(option.getLongOpt(), option.getValue());
                Object type = option.getType();
                if (type == null)
                {
                    continue;
                }
                if (type instanceof Integer)
                {
                    doExOpt((Integer) type, option.getValue());
                }
                else if (type instanceof ExOpt)
                {
                    doExOpt(((ExOpt) type).exopt, option.getValue());
                    radioSet.addAll(((ExOpt) type).radioParamList);
                    partnerSet.addAll(((ExOpt) type).partnerParamList);
                }
            }
            for (String param : partnerSet)
            {
                if (!map.containsKey(param))
                {
                    throw new Exception("缺少指定参数: " + param);
                }
            }
            for (String param : radioSet)
            {
                if (map.containsKey(param))
                {
                    throw new Exception("指定参数冲突: " + param);
                }
            }
            // inject params
            return map;
        }
        catch (Exception e)
        {
            System.err.println(e.getMessage());
            showUsage();
            System.exit(1);
        }
        return null;
    }

    private void doExOpt(Integer exopt, String value) throws Exception
    {
        if ((exopt & OPTION_FILE_EXIST) > 0)
        {
            File file = new File(value);
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
            File file = new File(value);
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
            File file = new File(value);
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
                Integer.parseInt(value);
            }
            catch (NumberFormatException e)
            {
                throw new Exception("不是有效的数字");
            }
        }
        if ((exopt & OPTION_IP) > 0)
        {
            if (!isIp(value))
            {
                throw new Exception("不是有效的ip");
            }
        }
        if ((exopt & OPTION_HOST) > 0)
        {
            try
            {
                Inet4Address.getByName(value);
            }
            catch (UnknownHostException e)
            {
                throw new Exception("不是有效的主机ip或域名");
            }
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
