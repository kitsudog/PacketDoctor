package sniffer.view;

import java.text.SimpleDateFormat;

import org.json.simple.JSONObject;

public interface IView
{

    static public class MessageData
    {
        /**
         * 消息标题(针对当前消息进行一个可读的标示)
         */
        public String title;

        /**
         * 消息id(进行一个初步的归类或者进行唯一标识的)
         */
        public String msgId;

        /**
         * 消息时间
         */
        public long timestamp;

        /**
         * 原始内容
         */
        public byte[] body;

        /**
         * 收/发(主要用于过滤)
         */
        public int type;

        /**
         * 当前包内容的解析为一个json对象进行展示
         */
        public JSONObject content;

        public static final SimpleDateFormat TIME_FORMAT = new SimpleDateFormat("HH:mm:ss.SSS");

        public static final String TITLE_FORMAT = "%s %s %s %s(%d)";

        public static final String[] TYPE = new String[]
        { "=>", "<=" };

        public static final int TYPE_SEND = 0;

        public static final int TYPE_RECV = 1;

        public MessageData(long time, String msgId, int type, String desc, JSONObject content, byte[] body)
        {
            this.timestamp = time;
            this.type = type;
            this.msgId = msgId;
            this.body = body;
            this.content = content;
            int size = 0;
            if (content != null)
            {
                size = content.keySet().size();
            }
            this.title = String.format(TITLE_FORMAT, TIME_FORMAT.format(time), TYPE[type], msgId, desc, size);
        }

        public static MessageData unknown(long time, String msgId, int type, byte[] body)
        {
            return new MessageData(time, msgId, type, "###UNKNOWN###", null, body);
        }
    }

    void setDebug(boolean debug);

    void addNode(MessageData data);

    void info(String msg);

    void alert(String msg);

    void error(String msg);

    void debug(String msg);

    String input(String msg, String defaultText);

    int confirm(String msg, String options[]);
}
