package pd;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.Inet4Address;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.cli.OptionBuilder;
import org.apache.commons.cli.Options;
import org.apache.pivot.wtk.DesktopApplicationContext;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapAddr;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

import pd.filter.BaseFilter;
import pd.handler.HandlerGenerator;
import pd.source.FileSource;
import pd.source.ISource;
import pd.source.LibPcapSource;
import pd.source.ProcessSource;
import pd.utils.CommandLineHelper;
import pd.utils.CommandLineHelper.ExOpt;
import pd.utils.IpUtils;
import pd.utils.ReleaseUtils;
import pd.utils.StringUtils;
import pd.view.ConsoleView;
import pd.view.GUIView;
import pd.view.IView;
import pd.view.PivotApplication;

@SuppressWarnings("static-access")
public class Main
{
    private static HashMap<String, String> defaultMap;

    private static IView console = new ConsoleView();

    private static Options options;

    private final PcapIf LOOP = new PcapIf();

    private final PcapIf FILE = new PcapIf();

    private final List<PcapIf> alldevs = new ArrayList<PcapIf>();

    private final StringBuilder errbuf = new StringBuilder();

    private HandlerGenerator handlerGenerator;

    private PcapIf device;

    private File pcapFile;

    private Integer port;

    private Integer host;

    private int skip;

    private IView view;

    private int[] deviceIp;

    private PDConfig conf;

    private String handler;

    private String sourceCmd;

    private ISource source;

    private int num = 1000000;

    private Main()
    {
        int r = Pcap.findAllDevs(alldevs, errbuf);
        if (r == Pcap.NOT_OK || alldevs.isEmpty())
        {
            console.alert(String.format("无法读取网卡列表, 尝试提高到管理员权限"));
            throw new Error();
        }
    }

    static
    {
        defaultMap = new HashMap<String, String>();
        defaultMap.put("handler", "DEFAULT");
        options = new Options();
        options.addOption(OptionBuilder.isRequired(false) //
                .withLongOpt("gui")//
                .withDescription("使用图形化界面")//
                .create("g"));
        options.addOption(OptionBuilder.isRequired(false) //
                .withLongOpt("debug")//
                .withDescription("只显示调试信息")//
                .create("d"));
        options.addOption(OptionBuilder.isRequired(false) //
                .withLongOpt("file")//
                .withDescription("指定文件")//
                .hasArg()//
                .withType(ExOpt.newOne(CommandLineHelper.OPTION_FILE_EXIST).partner("source"))//
                .create("f"));
        options.addOption(OptionBuilder.isRequired(false) //
                .withLongOpt("if")//
                .withDescription("指定接口")//
                .hasArg()//
                .create("i"));
        options.addOption(OptionBuilder.isRequired(false) //
                .withLongOpt("loop")//
                .withDescription("指定为lo 为接口")//
                .create("L"));
        options.addOption(OptionBuilder.isRequired(false) //
                .withLongOpt("port")//
                .withDescription("指定端口(仅截获与此端口的沟通)")//
                .withType(CommandLineHelper.OPTION_INT)//
                .hasArg()//
                .create("p"));
        options.addOption(OptionBuilder.isRequired(false) //
                .withLongOpt("host")//
                .withDescription("指定服务器ip或域名(仅截获与此主机的沟通)")//
                .withType(CommandLineHelper.OPTION_HOST)//
                .hasArg()//
                .create("h"));
        options.addOption(OptionBuilder.isRequired(false) //
                .withLongOpt("skip")//
                .withDescription("指定跳过的帧数(与file接口配合有意义)")//
                .withType(CommandLineHelper.OPTION_INT)//
                .hasArg()//
                .create("s"));
        options.addOption(OptionBuilder.isRequired(false) //
                .withLongOpt("source")//
                .withDescription("指定本机ip")//
                .withType(CommandLineHelper.OPTION_IP)//
                .hasArg()//
                .create("S"));
        options.addOption(OptionBuilder.isRequired(false)//
                .withLongOpt("conf")//
                .withDescription("指定配置文件")//
                .withType(CommandLineHelper.OPTION_FILE_EXIST)//
                .hasArg()//
                .create("c"));
        options.addOption(OptionBuilder.isRequired(false)//
                .withLongOpt("handler")//
                .withDescription("指定策略")//
                .hasArg()//
                .create("H"));
        options.addOption(OptionBuilder.isRequired(false)//
                .withLongOpt("list")//
                .withDescription("显示所有的网卡列表")//
                .create("l"));
        options.addOption(OptionBuilder.isRequired(false)//
                .withLongOpt("command")//
                .withDescription("不使用jnetpcap来获取数据 文件名变量为{}")//
                .withType(ExOpt.newOne().partner("source"))//
                .hasArg()//
                .create("C"));
        options.addOption(OptionBuilder.isRequired(false)//
                .withLongOpt("write")//
                .withDescription("导出到文件")//
                .withType(CommandLineHelper.OPTION_CAN_WRITE)//
                .hasArg()//
                .create("w"));
        options.addOption(OptionBuilder.isRequired(false)//
                .withLongOpt("num")//
                .withDescription("包的数量(默认1,000,000)")//
                .withType(CommandLineHelper.OPTION_INT)//
                .hasArg()//
                .create("n"));
        options.addOption(OptionBuilder.isRequired(false)//
                .withLongOpt("help")//
                .withDescription("显示帮助")//
                .create());
    }

    /**
     * 初始化PCAP的环境
     */
    private static void initEnv()
    {
        // 额外的dll拷贝到临时目录中去
        try
        {
            System.loadLibrary("jnetpcap");
        }
        catch (Throwable e)
        {
            String arch = System.getProperty("os.arch");
            String osname = System.getProperty("os.name");
            try
            {
                if (osname.equals("Windows"))
                {
                    ReleaseUtils.release(String.format("/pd/x86/jnetpcap.dll", arch));
                    ReleaseUtils.release(String.format("/pd/x86/pcap.dll", arch));
                }
                else if (osname.equals("Linux"))
                {
                    ReleaseUtils.release(String.format("/pd/%s/libjnetpcap.so", arch));
                    ReleaseUtils.release(String.format("/pd/%s/libpcap.so.0.9", arch));
                }
                else if (osname.equals("Mac"))
                {
                    // TODO:
                }
                else
                {
                    // TODO:
                }

                System.loadLibrary("jnetpcap");
            }
            catch (Throwable e2)
            {
                if (osname.equals("Windows"))
                {
                    console.error("请安装WinPCAP");
                }
                else if (osname.equals("Linux"))
                {
                    console.error("未知错误");
                }
                else if (osname.equals("Mac"))
                {
                    // TODO:
                }
                else
                {
                    // TODO:
                }
                e2.printStackTrace();
                throw new Error("无法继续");
            }
        }
    }

    private void showDeviceSelector()
    {
        String options[] = new String[alldevs.size() + 1];
        options[0] = "Loop [127.0.0.1]";
        int cnt = 1;
        for (PcapIf device : alldevs)
        {
            String description = (device.getDescription() != null) ? device.getDescription() : "没有合法的描述";
            options[cnt++] = (String.format("%s [%s]", device.getName(), description));
        }
        int result = view.confirm("输入目标网卡序号", options);
        if (result == 0)
        {
            device = LOOP;
            deviceIp = new int[]
            { IpUtils.string2int("127.0.0.1") };
        }
        else
        {
            device = alldevs.get(result - 1);
        }
    }

    public static void main(String[] args) throws Exception
    {
        CommandLineHelper helper = new CommandLineHelper("包监听工具", options, defaultMap);
        Map<String, String> paramMap = helper.parse(args);
        Main.initEnv();
        Main main = new Main();
        if (!helper.hasConsole())
        {
            // 默认开启gui模式
            paramMap.put("gui", "true");
            try
            {
                // 转储stdout与stderr
                PrintStream out = new PrintStream(new File("log"));
                System.setErr(out);
                System.setOut(out);
            }
            catch (FileNotFoundException e)
            {
                e.printStackTrace();
            }
        }
        if (paramMap.containsKey("gui"))
        {
            main.useGui();
        }
        else
        {
            main.useConsole();
        }
        if (paramMap.containsKey("help"))
        {
            helper.showUsage();
            return;
        }
        if (paramMap.containsKey("debug"))
        {
            main.view.setDebug(true);
        }
        if (paramMap.containsKey("list"))
        {
            String tmp = "";
            for (PcapIf dev : main.alldevs)
            {
                String ip = "";
                if (dev.getAddresses().size() > 0)
                {
                    for (PcapAddr addr : dev.getAddresses())
                    {
                        ip += IpUtils.bytes2string(addr.getAddr().getData()) + ", ";
                    }
                    ip = ip.replaceFirst(", $", "");
                }

                tmp += String.format("[%s]\t%-10s\t[%s]", ip, dev.getName(), dev.getDescription());
                tmp += "\n";
            }
            main.view.info(StringUtils.justify(tmp));
            return;
        }
        else if (paramMap.containsKey("file"))
        {
            main.device = main.FILE;
            main.pcapFile = new File(paramMap.get("file"));
            if (paramMap.containsKey("skip"))
            {
                main.skip = Integer.parseInt(paramMap.get("skip"));
            }
        }
        else if (paramMap.containsKey("loop"))
        {
            main.device = main.LOOP;
            main.deviceIp = new int[]
            { IpUtils.string2int("127.0.0.1") };
        }
        else if (paramMap.containsKey("if"))
        {
            main.device = main.getDeviceByName(paramMap.get("if"));
            List<PcapAddr> addrList = main.device.getAddresses();
            main.deviceIp = new int[addrList.size()];
            for (int i = 0; i < addrList.size(); i++)
            {
                PcapAddr addr = addrList.get(i);
                main.deviceIp[i] = IpUtils.bytes2int(addr.getAddr().getData());
            }
        }
        else if (paramMap.containsKey("command"))
        {
            main.sourceCmd = paramMap.get("command");
            main.device = main.FILE;
        }
        if (main.device == null)
        {
            main.showDeviceSelector();
        }
        if (paramMap.containsKey("host"))
        {
            main.host = IpUtils.bytes2int(Inet4Address.getByName(paramMap.get("host")).getAddress());
        }
        if (paramMap.containsKey("port"))
        {
            main.port = Integer.parseInt(paramMap.get("port"));
        }
        if (paramMap.containsKey("source"))
        {
            main.deviceIp = new int[]
            { IpUtils.string2int(paramMap.get("source")) };
        }
        if (paramMap.containsKey("write"))
        {
            // TODO:
        }
        if (paramMap.containsKey("num"))
        {
            main.num = Integer.parseInt(paramMap.get("num"));
        }
        if (paramMap.containsKey("conf"))
        {
            main.conf = PDConfig.parse(new File(paramMap.get("conf")));
        }
        else
        {
            if (new File("config.prop").exists())
            {
                main.conf = PDConfig.parse(new File("config.prop"));
            }
            else
            {
                main.conf = PDConfig.DEFAULT;
            }
        }
        main.handler = paramMap.get("handler");
        main.start();
    }

    private PcapIf getDeviceByName(String name) throws UnknownHostException
    {
        byte[] ipaddr = IpUtils.int2bytes(0xffffffff);
        if (name.matches("([0-9]{1,3}\\.){3}[0-9]{1,3}"))
        {
            ipaddr = Inet4Address.getByName(name).getAddress();
        }
        if (name.matches("\\d+"))
        {
            return alldevs.get(Integer.parseInt(name) - 1);
        }
        else
        {
            for (PcapIf dev : alldevs)
            {
                if (name.equals(dev.getName()))
                {
                    return dev;
                }
                if (name.equals(dev.getDescription()))
                {
                    return dev;
                }
                for (PcapAddr addr : dev.getAddresses())
                {
                    if (Arrays.equals(ipaddr, addr.getAddr().getData()))
                    {
                        return dev;
                    }
                }
            }
        }
        throw new Error("无法识别的接口");
    }

    private void useConsole()
    {
        view = new ConsoleView();
    }

    private void useGui()
    {
        DesktopApplicationContext.main(PivotApplication.class, new String[] {});
        while (PivotApplication.window == null)
        {
            try
            {
                Thread.sleep(10);
            }
            catch (InterruptedException e)
            {
                e.printStackTrace();
            }
        }
        view = (GUIView) PivotApplication.window;
        view.info("GUI Ready");
    }

    private void start() throws Exception
    {
        handlerGenerator = new HandlerGenerator(conf.getHandlerClass(handler), view);
        BaseFilter filter = new BaseFilter();
        if (host != null)
        {
            filter.setHost(host);
        }
        if (port != null)
        {
            filter.setPort(port);
        }
        handlerGenerator.addFilter(filter);
        handlerGenerator.setSource(deviceIp);
        view.info("Handler: " + conf.getHandlerName(handler));
        view.info("Source: " + IpUtils.int2string(deviceIp));
        String osname = System.getProperty("os.name");
        if (device == LOOP)
        {
            if (osname.startsWith("Linux"))
            {
                sourceCmd = String.format("tcpdump -i lo -w {}");
            }
            else if (osname.startsWith("Windows"))
            {
                File temporaryExe = File.createTempFile("RawPcap", ".exe");
                FileOutputStream outputStream = new FileOutputStream(temporaryExe);
                byte[] array = new byte[8192];
                InputStream exeStream = Class.class.getResourceAsStream("/pd/x86/RawCap.exe");
                for (int j = exeStream.read(array); j != -1; j = exeStream.read(array))
                {
                    outputStream.write(array, 0, j);
                }
                outputStream.flush();
                outputStream.close();
                exeStream.close();
                Process proc = null;
                try
                {
                    proc = Runtime.getRuntime().exec(temporaryExe.getAbsolutePath() + " -h");
                }
                catch (IOException e)
                {
                    System.err.println("请确认用管理员身份打开");
                    System.exit(1);
                }
                BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()));
                String line;
                int devid = -1;
                while ((line = reader.readLine()) != null)
                {
                    if (line.indexOf("127.0.0.1") > 0)
                    {
                        devid = Integer.parseInt(line.split("\\.")[0].trim());
                        break;
                    }
                }
                if (devid == -1)
                {
                    view.alert("无法挂载loop");
                    System.exit(1);
                }
                sourceCmd = String.format("%s -f %s {}", temporaryExe.getPath(), devid);
            }
            else if (osname.startsWith("Mac"))
            {
            }
            view.info(String.format("WATCH: LOOP"));
            source = new ProcessSource(sourceCmd);
        }
        else if (sourceCmd != null)
        {
            view.info(String.format("WATCH: %-20s", sourceCmd));
            source = new ProcessSource(sourceCmd);
        }
        else if (device == FILE)
        {
            view.info(String.format("WATCH: %-20s", pcapFile.getPath()));
            source = new FileSource(pcapFile.getPath());
        }
        else
        {
            view.info(String.format("WATCH: %-20s %s", IpUtils.int2string(deviceIp), device.getName()));
            source = new LibPcapSource(device);
        }
        source.init();
        int cnt = skip;
        source.skip(skip);
        while (true)
        {
            if (++cnt > num)
            {
                break;
            }
            JPacket packet = source.next();
            Tcp tcp = packet.getHeader(new Tcp());
            Ip4 ip4 = packet.getHeader(new Ip4());
            handlerGenerator.nextPacket(cnt, ip4, tcp);
        }
        view.alert("捕获结束");
    }
}