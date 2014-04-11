package pd;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileReader;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import pd.handler.HttpHandler;
import pd.handler.PacketHandler;

/**
 * pd的配置
 * <p>
 * @author zhangming.luo 2014年4月11日
 * @see
 * @since 1.0
 */
public class PDConfig
{

    private static final HandlerConfig HTTP_HANDLER_CONFIG;

    public static final PDConfig DEFAULT;

    static class HandlerConfig
    {
        String handlerClassName;

        Set<String> depedency = new HashSet<String>();

        public String name;
    }

    static
    {
        HTTP_HANDLER_CONFIG = new HandlerConfig();
        HTTP_HANDLER_CONFIG.name = "Http";
        HTTP_HANDLER_CONFIG.handlerClassName = HttpHandler.class.getName();
        DEFAULT = new PDConfig();
    }

    private Map<String, HandlerConfig> handlerConfigs = new HashMap<String, HandlerConfig>();

    private String _default;

    private PDConfig()
    {
        _default = "Http";
        handlerConfigs.put("Http", HTTP_HANDLER_CONFIG);
    }

    public String getHandlerName(String handler)
    {
        HandlerConfig config = handlerConfigs.get(handler);
        return config.name;
    }

    @SuppressWarnings("unchecked")
    public Class<? extends PacketHandler> getHandlerClass(String handler) throws Exception
    {
        HandlerConfig config = handlerConfigs.get(handler);
        URLClassLoader loader = (URLClassLoader) ClassLoader.getSystemClassLoader();
        Method add = URLClassLoader.class.getDeclaredMethod("addURL", new Class[]
        { URL.class });
        add.setAccessible(true);
        for (String lib : config.depedency)
        {
            add.invoke(loader, new URL(lib));
        }
        return (Class<? extends PacketHandler>) Class.forName(config.handlerClassName);
    }

    public static PDConfig parse(String configStr) throws Exception
    {
        PDConfig config = new PDConfig();
        Properties properties = new Properties();
        properties.load(new ByteArrayInputStream(configStr.getBytes()));
        Enumeration<Object> keys = properties.keys();
        while (keys.hasMoreElements())
        {
            String key = (String) keys.nextElement();
            String value = properties.getProperty(key);
            String[] tmp = key.split("\\.");
            if (key.startsWith("handler."))
            {
                doHandler(config, tmp, value);
            }
            else if (key.startsWith("config."))
            {
                doConfig(config, tmp, value);
            }
        }
        config.handlerConfigs.put("DEFAULT", config.handlerConfigs.get(config._default));
        return config;
    }

    private static void doConfig(PDConfig config, String[] key, String value)
    {
        if (key[1].equals("default"))
        {
            config._default = value;
        }
    }

    private static void doHandler(PDConfig config, String[] key, String value)
    {
        String configName = key[1];
        HandlerConfig c = config.handlerConfigs.get(configName);
        if (c == null)
        {
            c = new HandlerConfig();
            config.handlerConfigs.put(configName, c);
        }
        if (key[2].equals("main"))
        {
            c.handlerClassName = value;
        }
        else if (key[2].equals("dep"))
        {
            for (String dep : value.split(","))
            {
                c.depedency.add(dep);
            }
        }
        else if (key[2].equals("name"))
        {
            c.name = value;
        }
    }

    public static PDConfig parse(File file) throws Exception
    {
        FileReader reader = new FileReader(file);
        BufferedReader br = new BufferedReader(reader);
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = br.readLine()) != null)
        {
            sb.append(line);
            sb.append("\n");
        }
        br.close();
        reader.close();
        return parse(sb.toString());
    }

}
