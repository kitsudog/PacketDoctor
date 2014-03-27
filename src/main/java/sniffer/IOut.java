package sniffer;

import java.text.SimpleDateFormat;
import java.util.Date;

import org.json.simple.JSONObject;

public interface IOut
{

    /**
     * 消息配置类
     * <p>
     * detailed comment
     * @author zhangming.luo 2013-4-24
     * @see
     * @since 1.0
     */
    static public class MessageData
    {
        /**
         * 消息标题
         */
        public String title;

        /**
         * 消息id
         */
        public String msgId;

        /**
         * 消息时间
         */
        public long timestamp;

        public byte[] body;

        public int type;

        public JSONObject content;

        public static final SimpleDateFormat TIME_FORMAT = new SimpleDateFormat("HH:mm:ss.SSS");

        public static final String TITLE_FORMAT = "%s %s %s %s(%d)";

        public static final String[] TYPE = new String[]
        { "=>", "<=" };

        public static final int TYPE_SEND = 0;

        public static final int TYPE_RECV = 1;

        public MessageData(Date time, String msgId, int type, String desc, JSONObject content, byte[] body)
        {
            this.timestamp = time.getTime();
            this.type = type;
            this.msgId = msgId;
            this.body = body;
            this.content = content;
            this.title = String.format(TITLE_FORMAT, TIME_FORMAT.format(time), TYPE[type], msgId, desc, content.keySet().size());
        }

        public static MessageData unknown(Date time, String msgId, int type, byte[] body)
        {
            return new MessageData(time, msgId, type, "###UNKNOWN###", null, body);
        }
    }

	void addNode(MessageData data);

}
