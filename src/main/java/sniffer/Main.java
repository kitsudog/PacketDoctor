package sniffer;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.Inet4Address;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;

import org.apache.commons.cli.OptionBuilder;
import org.apache.commons.cli.Options;
import org.apache.pivot.wtk.Alert;
import org.apache.pivot.wtk.DesktopApplicationContext;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapAddr;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

import sniffer.filter.BaseFilter;
import sniffer.handler.HandlerGenerator;
import sniffer.handler.HttpHandler;
import sniffer.uitls.CommandLineHelper;
import sniffer.uitls.EndlessFileInputStream;
import sniffer.uitls.IpUtils;
import sniffer.uitls.PCAPFileReader;
import sniffer.view.ConsoleView;
import sniffer.view.GUIView;
import sniffer.view.IView;
import sniffer.view.PivotApplication;

@SuppressWarnings("static-access")
public class Main
{
    private static HashMap<String, String> defaultMap;

    private static IView console = new ConsoleView();

    private static Options options;

    private PcapIf LOOP = new PcapIf();

    private PcapIf FILE = new PcapIf();

    private List<PcapIf> alldevs = new ArrayList<PcapIf>();

    private StringBuilder errbuf = new StringBuilder();

    private HandlerGenerator handlerGenerator;

    private PcapIf device;

    private File pcapFile;

    private Integer port;

    private Integer host;

    private int skip;

    private IView view;

    private Main()
    {
        int r = Pcap.findAllDevs(alldevs, errbuf);
        if (r == Pcap.NOT_OK || alldevs.isEmpty())
        {
            console.alert(String.format("无法读取网卡列表, error is %s", errbuf.toString()));
            throw new Error();
        }
    }

    static
    {
        defaultMap = new HashMap<String, String>();
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
                .withType(CommandLineHelper.OPTION_FILE_EXIST)//
                .create("f"));
        options.addOption(OptionBuilder.isRequired(false) //
                .withLongOpt("if")//
                .withDescription("指定接口")//
                .hasArg()//
                .create("i"));
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
            String libpath = System.getProperty("java.library.path");
            if (libpath == null || libpath.length() == 0)
            {
                throw new RuntimeException("无法自动释放jnetpcap, 请设置一个拥有写权限的目录-Djava.library.path=");
            }
            String path = null;
            StringTokenizer st = new StringTokenizer(libpath, System.getProperty("path.separator"));

            while (true)
            {
                if (!st.hasMoreTokens())
                {
                    throw new RuntimeException("无法自动释放jnetpcap, 请设置一个拥有写权限的目录-Djava.library.path=");
                }
                path = st.nextToken();
                File temporaryLib = new File(new File(path), "jnetpcap");
                if (temporaryLib.exists())
                {
                    throw new RuntimeException("释放的jnetpcap库无效");
                }
                try
                {
                    FileOutputStream outputStream = new FileOutputStream(temporaryLib);
                    byte[] array = new byte[8192];
                    InputStream libStream = null;
                    if (osname.startsWith("Linux"))
                    {
                        libStream = Main.class.getResourceAsStream(arch.equals("x86") ? "libjnetpcap.so" : "libjnetpcap-64.so");
                    }
                    else if (osname.startsWith("Windows"))
                    {
                        libStream = Main.class.getResourceAsStream(arch.equals("x86") ? "jnetpcap.dll" : "jnetpcap-64.dll");
                    }
                    else if (osname.startsWith("Mac"))
                    {

                    }
                    for (int i = libStream.read(array); i != -1; i = libStream.read(array))
                    {
                        outputStream.write(array, 0, i);
                    }
                    outputStream.flush();
                    outputStream.close();
                    libStream.close();
                    console.info("释放jnetpacp到目录 " + path);
                    try
                    {
                        System.load(temporaryLib.getPath());
                        console.info("使用临时目录的库 " + path);
                        break;
                    }
                    catch (Throwable e2)
                    {
                        console.info("无法使用库" + path + " " + e2.getMessage());
                    }
                }
                catch (Throwable e1)
                {
                    // 尝试下一个
                    console.info("无法释放库到目录" + path + " " + e1.getMessage());
                    if (temporaryLib.exists())
                    {
                        temporaryLib.delete();
                    }
                }
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
        }
        else
        {
            device = alldevs.get(result - 1);
        }
    }

    private void startWithLoop() throws IOException
    {
        File temporaryExe = File.createTempFile("RawPcap", ".exe");
        FileOutputStream outputStream = new FileOutputStream(temporaryExe);
        byte[] array = new byte[8192];
        InputStream exeStream = Main.class.getResourceAsStream("RawCap.exe");
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
        File tempFile = File.createTempFile("dump", ".pcap");
        // 正式启动cap
        try
        {
            final Process subproc = Runtime.getRuntime().exec(temporaryExe.getAbsolutePath() + " -f " + devid + " " + tempFile.getAbsolutePath());
            Runtime.getRuntime().addShutdownHook(new Thread(new Runnable()
            {
                @Override
                public void run()
                {
                    subproc.destroy();
                }
            }));
            skip = 0;
            startWithFile(tempFile, true);
            subproc.destroy();
            tempFile.delete();
            temporaryExe.delete();
        }
        catch (SecurityException e)
        {
            Alert.alert("请使用管理员的cmd启动", PivotApplication.window);
        }
    }

    private void startWithFile(File file, boolean manualStop) throws IOException
    {
        PCAPFileReader reader = new PCAPFileReader(new EndlessFileInputStream(file));
        int cnt = skip;
        reader.skip(skip);
        while (true)
        {
            if (!manualStop && !reader.hasNext())
            {
                break;
            }
            byte[] buffer = reader.next();
            try
            {
                if (++cnt > 1000000)
                {
                    break;
                }
                JMemoryPacket packet = new JMemoryPacket(JProtocol.ETHERNET_ID, Arrays.copyOfRange(buffer, 16, buffer.length));
                Tcp tcp = packet.getHeader(new Tcp());
                Ip4 ip4 = packet.getHeader(new Ip4());
                handlerGenerator.nextPacket(ip4, tcp);
            }
            catch (Throwable e)
            {
                System.err.println("无法解析的包 " + cnt);
                byte[] buff = Arrays.copyOfRange(buffer, 16, buffer.length);
                for (int i = 0; i < buff.length; i++)
                {
                    System.err.print(String.format("%02x ", buff[i]));
                    if ((i + 1) % 16 == 0)
                    {
                        System.err.println();
                    }
                }
                System.err.println();
                e.printStackTrace();
            }
        }
    }

    private void startWithPcap()
    {
        int snaplen = 64 * 1024;
        int flags = Pcap.MODE_PROMISCUOUS;
        int timeout = 1 * 1000;
        Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
        int cnt = 0;
        while (cnt < 1000000)
        {
            pcap.loop(1000, handlerGenerator, "jNetPcap rocks!");
        }
        pcap.close();
    }

    public static void main(String[] args) throws Exception
    {
        Map<String, String> paramMap = new CommandLineHelper("包监听工具", options, defaultMap).parse(args);
        Main.initEnv();
        Main main = new Main();
        if (paramMap.containsKey("gui"))
        {
            main.useGui();
        }
        else
        {
            main.useConsole();
        }

        if (paramMap.containsKey("debug"))
        {
            main.view.setDebug(true);
        }

        if (paramMap.containsKey("file"))
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
        }
        else if (paramMap.containsKey("if"))
        {
            main.device = main.getDeviceByName(paramMap.get("if"));
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

        main.start();
    }

    private PcapIf getDeviceByName(String name) throws UnknownHostException
    {
        if (name.matches("([0-9]{1,3}\\.){3}[0-9]{1,3}"))
        {
            byte[] ipaddr = Inet4Address.getByName(name).getAddress();
            for (PcapIf dev : alldevs)
            {
                if (dev.getName().equals(name))
                {
                    return dev;
                }
                if (dev.getDescription().equals(name))
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
            throw new Error("没有找到指定ip的设备");
        }
        else if (name.matches("\\d+"))
        {
            return alldevs.get(Integer.parseInt(name) - 1);
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

    private void start() throws IOException
    {
        handlerGenerator = new HandlerGenerator(HttpHandler.class, view);
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
        if (device == LOOP)
        {
            view.info(String.format("WATCH: LOOP"));
            startWithLoop();
        }
        else if (device == FILE)
        {
            view.info(String.format("WATCH: %s", pcapFile.getPath()));
            startWithFile(pcapFile, false);
        }
        else
        {
            view.info(String.format("WATCH: %20s %s", device.getAddresses().get(0).getAddr(), device.getName()));
            startWithPcap();
        }
        view.alert("捕获结束");
    }

}