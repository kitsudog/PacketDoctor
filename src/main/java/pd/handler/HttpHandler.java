package pd.handler;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;

import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

import pd.utils.Asserts;
import pd.view.IView.MessageData;

import com.alibaba.fastjson.JSONObject;

public class HttpHandler extends TcpHandler
{

    public abstract class Http
    {
        public int headerLength = -2;

        public int length = -1;

        public byte[] content;

        public String command;

        public long timestamp;

        public HashMap<String, String> headerMap = new HashMap<String, String>();

        public String uri;

        public String url;

        @Override
        public String toString()
        {
            String key = url;
            if (key == null)
            {
                key = command;
            }
            return key + "\n" + headerMap + "\n" + (content == null ? "###EMPTY###" : new String(content));
        }
    }

    public class Request extends Http
    {

    }

    public class Response extends Http
    {
        public int status;
    }

    public static Pattern REQUEST_COMMAND = Pattern.compile("(GET|POST) ([^ ]+) HTTP/[0-9.]+");

    public static Pattern RESPONSE_COMMAND = Pattern.compile("HTTP/[0-9.]+ (\\d+)( \\w+)?");

    public static int STATE_NONE = 0;

    public static int STATE_REQUEST = 1;

    public static int STATE_RESPONSE = 2;

    private Http state = null;

    private Request request = null;

    private Response response = null;

    private List<byte[]> raws = null;

    @Override
    protected void sendTcp(Ip4 ip4, Tcp tcp, byte[] payload, long timestamp)
    {
        doTcp(ip4, tcp, payload, timestamp);
    }

    @Override
    protected void recvTcp(Ip4 ip4, Tcp tcp, byte[] payload, long timestamp)
    {
        doTcp(ip4, tcp, payload, timestamp);
    }

    private void doTcp(Ip4 ip4, Tcp tcp, byte[] data, long timestamp)
    {
        if (data.length == 0)
        {
            return;
        }
        if (state == null)
        {
            Asserts.isNull(request, response);
            switch (data[0])
            {
                case 'G':
                    if (data[1] == 'E' && data[2] == 'T')
                    {
                        isRequest("GET");
                    }
                    else
                    {
                        return;
                    }
                    break;
                case 'P':
                    if (data[1] == 'O' && data[2] == 'S' && data[3] == 'T')
                    {
                        isRequest("POST");
                    }
                    else
                    {
                        return;
                    }
                    break;
                case 'H':
                    if (data[1] == 'T' && data[2] == 'T' && data[3] == 'P')
                    {
                        isRespsone();
                    }
                    else
                    {
                        return;
                    }
                    break;
                default:
                    // 中间获取的不要了
                    return;
            }
            state.timestamp = timestamp;
        }
        if (state.length < 0)
        {
            try
            {
                addRaw(data);
                doHeader();
            }
            catch (Exception e)
            {
                e.printStackTrace();
                view.error(request.toString());
                view.error(response.toString());
            }
        }
        else
        {
            try
            {
                addRaw(data);
            }
            catch (Exception e)
            {
                e.printStackTrace();
            }
        }
        if (state.length == -1)
        {
            return;
        }

        if (getRawSize() >= state.length)
        {
            try
            {
                doHttp();
            }
            catch (Exception e)
            {
                e.printStackTrace();
                view.error(request.toString());
                view.error(response.toString());
            }
        }
    }

    private void doHeader()
    {
        byte[] data = getRaw();
        String sign = new String(Arrays.copyOfRange(data, 0, 4));
        if (sign.equals("HTTP"))
        {
            isRespsone();
        }
        else if (sign.startsWith("GET") || sign.startsWith("POST"))
        {
            isRequest(sign);
        }
        else
        {
            view.error(new String(getRaw()));
            throw new RuntimeException("未知的类型");
        }

        state.headerLength = -3;
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
        if (state.headerLength < 0)
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

    private void isNull()
    {
        request = null;
        response = null;
        state = null;
        resetRaw();
    }

    private void isRequest(String method)
    {
        if (state == request && request != null)
        {
            return;
        }
        request = new Request();
        response = new Response();
        state = request;
        allocateRaw();
    }

    private void isRespsone()
    {
        if (state == response && response != null)
        {
            return;
        }
        if (request == null)
        {
            request = new Request();
        }
        if (response == null)
        {
            response = new Response();
        }
        state = response;
        allocateRaw();
    }

    private void waitResponse()
    {
        Asserts.isNotNull(request, response);
        state = response;
        allocateRaw();
    }

    private void doRequest()
    {
        String tmp = state.headerMap.get("Content-Length");
        if (tmp != null)
        {
            state.length = state.headerLength + Integer.parseInt(tmp);
        }
        else
        {
            state.length = state.headerLength;
        }
        Matcher matcher = REQUEST_COMMAND.matcher(request.command);
        matcher.find();
        request.uri = matcher.group(2);
        request.url = "http://" + request.headerMap.get("Host") + request.uri;
    }

    private void doResponse()
    {
        String tmp = state.headerMap.get("Content-Length");
        int contentLength = tmp == null ? (getRawSize() - state.headerLength) : Integer.parseInt(tmp);
        state.length = state.headerLength + contentLength;
        Matcher matcher = RESPONSE_COMMAND.matcher(response.command);
        matcher.find();
        response.status = Integer.parseInt(matcher.group(1));
    }

    private void doHttp()
    {
        if (state.headerLength < 0)
        {// PATCH
            doHeader();
            view.error("出现越界错误了\n" + request);
        }
        byte[] data = getRaw();
        byte[] contentRaw = Arrays.copyOfRange(data, state.headerLength, data.length);
        if (contentRaw.length == 0)
        {
        }
        else
        {
            String contentEncoding = state.headerMap.get("Content-Encoding");
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
                                if (contentRaw.length < i + chunkSize + 2 + 5)
                                {
                                    // 数据还不够
                                    state.length += i + chunkSize + 2 + 5 - contentRaw.length;
                                    return;
                                }
                                buff.write(Arrays.copyOfRange(contentRaw, i, i + chunkSize));
                            }
                            else
                            {
                                state.length += 2;
                                break;
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
            if (contentEncoding != null && contentEncoding.equals("gzip"))
            {
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                try
                {
                    GZIPInputStream gis = new GZIPInputStream(new ByteArrayInputStream(contentRaw));
                    byte[] buff = new byte[1024];
                    int cnt = 0;
                    while ((cnt = gis.read(buff)) != -1)
                    {
                        out.write(buff, 0, cnt);
                    }
                    gis.close();
                    out.close();
                }
                catch (Exception e)
                {
                    view.error(request.url + "\n" + e.getMessage());
                    e.printStackTrace();
                }
                state.content = out.toByteArray();
            }
            else
            {
                state.content = contentRaw;
            }
        }
        if (state == request)
        {
            waitResponse();
        }
        else
        {
            if (request.length == -1)
            {
                view.error("不完整\n" + response);
            }
            else
            {
                doHttp(request, response);
            }
            isNull();
        }
    }

    protected void doHttp(Request request, Response response)
    {
        JSONObject req = new JSONObject(true);
        // req.putAll(request.headerMap);
        String reqType = response.headerMap.get("Content-Type");
        if (request.content != null)
        {
            if (reqType != null)
            {
                if (reqType.equals("application/x-www-form-urlencoded"))
                {
                    req.put("content", new String(request.content));
                }
                else if (reqType.startsWith("text"))
                {
                    req.put("content", new String(request.content));
                }
                else
                {
                    req.put("content", String.format("###%s###", reqType.toUpperCase()));
                }
            }
            else
            {
                req.put("content", String.format("###未指定类型###\t%s", new String(request.content)));
            }
        }
        view.addNode(new MessageData(request.timestamp, request.url, MessageData.TYPE_SEND, "", req, request.content));

        JSONObject res = new JSONObject(true);
        req.putAll(response.headerMap);
        String resType = response.headerMap.get("Content-Type");
        if (response.content != null)
        {
            if (resType != null)
            {
                if (resType.startsWith("text") || resType.indexOf("html") >= 0 || resType.indexOf("json") >= 0 || resType.indexOf("javascript") >= 0)
                {
                    res.put("content", new String(response.content));
                }
                else
                {
                    res.put("content", String.format("###%s###", resType.toUpperCase()));
                }
            }
            else
            {
                res.put("content", String.format("###未指定类型###\t%s", new String(response.content)));
            }
        }
        else
        {
            res.put("content", String.format("###空###\t%s", response.status));
        }
        view.addNode(new MessageData(request.timestamp, request.url + ":" + response.status, MessageData.TYPE_RECV, "", res, response.content));

    }

    protected void resetRaw()
    {
        raws = new LinkedList<byte[]>();
    }

    protected void allocateRaw()
    {
        raws = new LinkedList<byte[]>();
    }

    protected void addRaw(byte[] data)
    {
        raws.add(data);
    }

    protected byte[] getRaw()
    {
        byte result[] = new byte[getRawSize()];
        int pos = 0;
        for (byte[] i : raws)
        {
            System.arraycopy(i, 0, result, pos, i.length);
            pos += i.length;
        }
        return result;
    }

    protected int getRawSize()
    {
        int size = 0;
        for (byte[] i : raws)
        {
            size += i.length;
        }
        return size;
    }

}
