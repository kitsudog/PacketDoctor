package sniffer.game.ggsg;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;

import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

public class HttpHandler extends AbstractPacketHandler
{

    private ByteArrayOutputStream raw;

    public static Pattern REQUEST_COMMAND = Pattern.compile("(GET|POST) ([^ ]+) HTTP/[0-9.]+");

    public static Pattern RESPONSE_COMMAND = Pattern.compile("HTTP/[0-9.]+ (\\d+)( \\w+)?");

    public static int STATE_NONE = 0;

    public static int STATE_REQUEST = 1;

    public static int STATE_RESPONSE = 2;

    private Http state = null;

    public abstract class Http
    {
        public int headerLength;

        public int length = -1;

        public byte[] content;

        public String command;

        public HashMap<String, String> headerMap = new HashMap<String, String>();

        @Override
        public String toString()
        {
            return command + "\n" + headerMap + "\n" + (content == null ? "###EMPTY###" : new String(content));
        }
    }

    public class Request extends Http
    {
        public String uri;

        public String url;
    }

    public class Response extends Http
    {
        public int status;
    }

    private Request request;

    private Response response;

    @Override
    final public void nextPacket(Ip4 ip4, Tcp tcp, long timestamp)
    {
        byte[] data = tcp.getPayload();
        if (data.length == 0)
        {
            return;
        }
        if (state == null)
        {
            request = new Request();
            response = new Response();
            state = request;
            raw = new ByteArrayOutputStream();
        }
        if (state.length < 0)
        {
            switch (data[0])
            {
                case 'G':
                    if (data[1] == 'E' && data[2] == 'T')
                    {
                        break;
                    }
                    else
                    {
                        return;
                    }
                case 'P':
                    if (data[1] == 'O' && data[2] == 'S' && data[3] == 'T')
                    {
                        break;
                    }
                    else
                    {
                        return;
                    }
                case 'H':
                    if (data[1] == 'T' && data[2] == 'T' && data[3] == 'P')
                    {
                        break;
                    }
                    else
                    {
                        return;
                    }
                default:
                    // 中间获取的不要了
                    return;
            }
            try
            {
                raw.write(data);
                doHeader();

            }
            catch (IOException e)
            {
                e.printStackTrace();
            }
        }
        else
        {
            try
            {
                raw.write(data);
            }
            catch (IOException e)
            {
                e.printStackTrace();
            }
        }
        if (state.length == -1)
        {
            return;
        }
        if (raw.size() >= state.length)
        {
            doHttp();
        }
    }

    private void doHeader()
    {
        byte[] data = raw.toByteArray();
        state = new String(Arrays.copyOfRange(data, 0, 4)).equals("HTTP") ? response : request;
        state.headerLength = -1;
        for (int i = 0; i < data.length - 3; i++)
        {
            if (data[i] == '\r'//
                    && data[i + 1] == '\n'//
                    && data[i + 2] == '\r'//
                    && data[i + 3] == '\n'//
            )
            {
                state.headerLength = i + 4;
                break;
            }
        }
        if (state.headerLength == -1)
        {
            // 等待后续的数据
            return;
        }
        String header = new String(Arrays.copyOfRange(data, 0, state.headerLength));
        state.headerMap = new HashMap<String, String>();
        String[] headers = header.split("\r\n");
        state.command = headers[0];
        if (headers.length > 1)
        {
            for (String line : Arrays.copyOfRange(headers, 1, headers.length))
            {
                int i = line.indexOf(":");
                state.headerMap.put(line.substring(0, i), line.substring(i + 1).trim());
            }
        }
        if (header.startsWith("HTTP"))
        {
            doResponse();
        }
        else
        {
            doRequest();
        }

    }

    private void doRequest()
    {
        state.length = state.headerLength;
        Matcher matcher = REQUEST_COMMAND.matcher(request.command);
        matcher.find();
        request.uri = matcher.group(2);
        request.url = "http://" + request.headerMap.get("Host") + request.uri;
    }

    private void doResponse()
    {
        String tmp = state.headerMap.get("Content-Length");
        int contentLength = tmp == null ? (raw.size() - state.headerLength) : Integer.parseInt(tmp);
        state.length = state.headerLength + contentLength;
        Matcher matcher = RESPONSE_COMMAND.matcher(response.command);
        matcher.find();
        response.status = Integer.parseInt(matcher.group(1));
    }

    private void doHttp()
    {
        byte[] data = raw.toByteArray();
        byte[] contentRaw = Arrays.copyOfRange(data, state.headerLength, data.length);
        if (contentRaw.length == 0)
        {
        }
        else
        {
            String contentEncoding = state.headerMap.get("Content-Encoding");
            if (contentEncoding != null && contentEncoding.equals("gzip"))
            {
                if ("chunked".equals(state.headerMap.get("Transfer-Encoding")))
                {
                    // 寻找对应的chunked
                    int cur = 0;
                    int chunkSize = 0;
                    ByteArrayOutputStream buff = new ByteArrayOutputStream();
                    try
                    {
                        for (int i = cur; i < contentRaw.length - 1; i++)
                        {
                            if (contentRaw[i] == '\r' && contentRaw[i + 1] == '\n')
                            {
                                chunkSize = 0;
                                if (i == cur)
                                {
                                    cur = i + 2;
                                    i += 1;
                                    continue;
                                }
                                for (byte b : Arrays.copyOfRange(contentRaw, cur, i))
                                {
                                    chunkSize <<= 4;
                                    chunkSize |= b > '9' ? ((b | 32) - ('a' - 10)) : (b - '0');
                                }
                                i += 2;
                                if (chunkSize > 0)
                                {
                                    if (contentRaw.length < i + chunkSize)
                                    {
                                        // 数据还不够
                                        state.length += i + chunkSize - contentRaw.length;
                                        return;
                                    }
                                    buff.write(Arrays.copyOfRange(contentRaw, i, i + chunkSize));
                                }
                                cur = chunkSize + i + 2;
                                i = cur - 1;
                            }
                        }
                    }
                    catch (IOException e)
                    {
                        e.printStackTrace();
                    }
                    contentRaw = buff.toByteArray();
                }
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                try
                {
                    GZIPInputStream gis = new GZIPInputStream(new ByteArrayInputStream(contentRaw));
                    byte[] buff = new byte[1024];
                    try
                    {
                        int cnt = 0;
                        while ((cnt = gis.read(buff)) != -1)
                        {
                            out.write(buff, 0, cnt);
                        }
                        gis.close();
                    }
                    catch (Exception e)
                    {
                        e.printStackTrace();
                    }
                    out.close();
                }
                catch (Exception e)
                {
                    System.err.println(request.url + e.getMessage());
                    e.printStackTrace();
                }
                state.content = out.toByteArray();
            }
            else
            {
                state.content = contentRaw;
            }
        }
        try
        {
            raw.close();
        }
        catch (IOException e)
        {
            e.printStackTrace();
        }
        raw = null;
        if (state == request)
        {
            state = response;
            raw = new ByteArrayOutputStream();
        }
        else
        {
            if (request.length == -1)
            {
                System.err.println("不完整");
                System.err.println(response);
            }
            else
            {
                doHttp(request, response);
            }
            state = null;
        }

    }

    protected void doHttp(Request request, Response response)
    {
        System.out.println("REQUEST: " + request.url);
        String type = response.headerMap.get("Content-Type");
        if (response.content != null)
        {
            if (type != null)
            {
                if (type.startsWith("text") || type.indexOf("html") >= 0 || type.indexOf("json") >= 0 || type.indexOf("javascript") >= 0)
                {
                    System.out.println("\t" + new String(response.content).replaceAll("\\n|\\r", "\\\\n"));
                }
                else
                {
                    System.out.println("\t" + type.toUpperCase());
                }
            }
            else
            {
                System.out.println("\t未知\t" + new String(response.content).replaceAll("\\n|\\r", "\\\\n"));
            }
        }
        else
        {
            System.out.println("\t空 " + response.status);
        }
    }
}
