package sniffer.utils;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.Map;
import java.util.Map.Entry;
import java.util.PriorityQueue;
import java.util.Queue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;

/**
 * 
 * 调优专用工具类
 * <p>
 * 主要提供一些常用的调优函数接口
 * @author zhangming.luo 2013-3-20
 * @see
 * @since 1.0
 */
final public class Profiles
{

    public static boolean DEBUG = false;

    public static final String TOO_MANY_LEVEL = "ProfileError_Too_Many_Level";

    public static final String TOO_MANY_NODE = "ProfileError_Too_Many_Node";

    public static final String NO_START = "ProfileError_No_Start";

    public static final String START = "ProfileStart";

    public static final String END = "ProfileEnd";

    public static final String INIT_NODE = "ProfileInit";

    public static final String INVALID = "ProfileInvalid";

    private static Logger logger = Logger.getLogger("profile");

    private static Map<String, ProfileNode> nodes = new HashMap<String, ProfileNode>(1024);

    private static int maxLength;

    public static final ThreadLocal<ProfileChildNodeSet> session = new ThreadLocal<ProfileChildNodeSet>();

    public static final ProfileNode RESERVE_NODE = new ProfileNode("严重违规使用Profiles");

    static
    {
        nodes.put(RESERVE_NODE.title, RESERVE_NODE);
    }

    public static void initNode(Collection<String> titles)
    {
        for (String title : titles)
        {
            initNode(title);
        }
    }

    public static void initNode(File file)
    {
        try
        {
            BufferedReader reader = new BufferedReader(new FileReader(file));
            initNode(reader.readLine());
            reader.close();
        }
        catch (IOException e)
        {
        }
    }

    public static ProfileNode initNode(String title)
    {
        // TODO: 对于多线程的冲突可以从两个方向入手
        // 1. Profiles本身完全基于线程实现,不考虑多线程之间的交叉,保证在dump的时候遍历所有的线程来获取最终的结果
        // 缺点是存在销毁线程时则数据丢失
        // 2. 采用Disruptor实现一个ringbuffer来实现获取Node的操作
        // 缺点是内存开销相对会比较大,而且当出现大延迟的Profile单元时会影响到整个系统
        synchronized (nodes)
        {
            long start = System.nanoTime();
            ProfileNode node = nodes.get(title);
            if (node == null)
            {
                if (nodes.size() > 10000)
                {
                    // 严重违规使用了
                    // 超标的使用Profile会导致性能瘫痪
                    sampling(TOO_MANY_NODE, 0, 0);
                    logger.error(String.format("Profiles所监控的点超标了 %s", title));
                    node = RESERVE_NODE;
                }
                else
                {
                    node = new ProfileNode(title);
                    nodes.put(title, node);
                    // title最好不要出现冲突否则统计将不准确
                    maxLength = Math.max(maxLength, title.length());
                    if (nodes.size() % 1000 == 0)
                    {
                        logger.warn(String.format("Profiles所监控的点数量有点多了 %d", nodes.size()));
                    }
                }
            }
            // 此时获取方法已经正常了所以不用担心死锁
            sampling(INIT_NODE, start, System.nanoTime());
            return node;
        }
    }

    private static ProfileChildNode getNode(String title, ProfileChildNodeSet set)
    {
        ProfileNode node = nodes.get(title);
        if (node == null)
        {
            node = initNode(title);
        }
        ProfileNode orig = node;
        ProfileChildNode childNode = set.getNode(title);
        childNode.source = orig;
        // 标记已经启动了
        childNode.start = 1;
        return childNode;
    }

    private static ProfileNode getNodeOnly(String title)
    {
        ProfileNode node = nodes.get(title);
        if (node == null)
        {
            node = initNode(title);
        }
        return node;
    }

    /**
     * 提供给测试用的
     */
    public static void clean()
    {
        synchronized (nodes)
        {
            nodes.clear();
        }
    }

    /**
     * 重置所有的数值<br>
     * 但不清理保证了后续使用时的速度
     */
    public static void reset()
    {
        Queue<ProfileNode> queue = getNodes(true);
        for (String str : format(queue))
        {
            logger.info(str);
        }
    }

    /**
     * 将初始化的信息写入到文件(全部都是key而已)
     * @param filePath
     */
    public static void dumpInitInfoToFile(String filePath)
    {
        Queue<ProfileNode> nodes = getNodes(false);
        StringBuilder sb = new StringBuilder();
        for (Iterator<ProfileNode> it = nodes.iterator(); it.hasNext();)
        {
            sb.append(it.next().title).append('\n');
        }
        try
        {
            FileWriter writer = new FileWriter(new File(filePath));
            writer.write(sb.toString());
            writer.close();
        }
        catch (IOException e)
        {
        }
    }

    private static Queue<ProfileNode> getNodes(boolean clear)
    {
        Queue<ProfileNode> queue = new LinkedList<ProfileNode>();
        synchronized (nodes)
        {
            // 马上复制一份
            for (ProfileNode node : nodes.values())
            {
                // 通过克隆来保证多线程的屏蔽
                queue.add(node.clone());
            }
            if (clear)
            {
                HashMap<String, ProfileNode> newNodes = new HashMap<String, ProfileNode>(1024);
                for (Entry<String, ProfileNode> entry : nodes.entrySet())
                {
                    ProfileNode newNode = entry.getValue().clone();
                    newNode.clean();
                    newNodes.put(entry.getKey(), newNode);
                }
                nodes = newNodes;
            }
        }
        PriorityQueue<ProfileNode> tmp = new PriorityQueue<ProfileNode>(queue.size() + 1, new Comparator<ProfileNode>()
        {
            @Override
            public int compare(ProfileNode o1, ProfileNode o2)
            {
                long r = 0;
                if (o1.has1ms() ^ o2.has1ms())
                {
                    if (o1.has1ms())
                    {
                        return 1;
                    }
                    else
                    {
                        return -1;
                    }
                }
                r = o1.ravg() - o2.ravg();
                if (r != 0)
                {
                    if (r > 0)
                    {
                        return 1;
                    }
                    else
                    {
                        return -1;
                    }
                }
                r = o1.sum.get() - o2.sum.get();
                if (r != 0)
                {
                    if (r > 0)
                    {
                        return 1;
                    }
                    else
                    {
                        return -1;
                    }
                }
                r = o1.max - o2.max;
                if (r != 0)
                {
                    if (r > 0)
                    {
                        return 1;
                    }
                    else
                    {
                        return -1;
                    }
                }
                return o1.title.compareTo(o2.title);
            }
        });
        tmp.addAll(queue);
        return tmp;
    };

    /**
     * 打印出所有的统计情况
     */
    synchronized public static String[] dump()
    {
        Queue<ProfileNode> queue = getNodes(false);
        return format(queue);
    }

    synchronized public static String[] dumpProfile()
    {
        Queue<ProfileNode> queue = new LinkedBlockingQueue<ProfileNode>();
        queue.add(nodes.get(START));
        queue.add(nodes.get(END));
        return format(queue);
    }

    private static String[] format(Queue<ProfileNode> queue)
    {
        String title = String.format("%-1s|\t%8s\t%8s\t%8s\t%8s\t%8s\t%8s", doubleChar("title", maxLength * 2), "cnt", "ravg(us)", "avg(us)", ">1000us%",
                "min(us)", "max(us)");
        String[] result = new String[queue.size() + 1];
        int i = 0;
        result[i++] = title;
        String template = "%-1s|\t%8d\t%8s\t%8s\t%8s\t%8d\t%8d";
        while (queue.size() > 0)
        {
            ProfileNode node = queue.poll();
            if (node.title == RESERVE_NODE.title)
            {
                continue;
            }
            if (node.cnt.get() == 0)
            {
                continue;
            }
            if (node.min == Long.MAX_VALUE)
            {
                sampling(INVALID, 0, 0);
                result[i++] = String.format(template, doubleChar(node.title, maxLength * 2), node.cnt.get(), (int) node.avg(), (int) node.ravg(), 0, -1,
                        node.max);
                continue;
            }
            String tmp = String.format(template//
                    , doubleChar(node.title, maxLength * 2)//
                    , node.cnt.get()//
                    , node.sum.get() == 0 ? //
                    "0" //
                            : String.format("%8d", node.ravg() / 1000)//
                    , node.sum.get() == 0 ? //
                    "0" //
                            : (//
                            node.avg() < 1000 ? //
                            String.format("%8.3f", node.avg() / 1000.0)//
                                    : String.valueOf(node.avg() / 1000l)//
                            )//
                    , (node.cnt.get() - node.ucnt.get() == 0) ? //
                    "0" //
                            : (//
                            (node.ucnt.get() == 0) ? //
                            "100" //
                                    : String.format("%8.2f", (100 - node.ucnt.get() * 100.0 / node.cnt.get()))//
                            )//
                    , node.min / 1000//
                    , node.max / 1000//
                    );
            result[i++] = tmp;
        }
        return result;
    }

    private static String doubleChar(String title, int length)
    {
        length = (int) (Math.ceil(length / 8d) * 8);
        int cnt = length - title.length();
        for (char c : title.toCharArray())
        {
            if (c < 128 && c > 0)
            {
                ;
            }
            else
            {
                cnt--;
            }
        }
        while (cnt > 0)
        {
            title += " ";
            cnt--;
        }
        return title;
    }

    /**
     * 延迟采样
     * @param title
     * @param start
     * @param end
     */
    public static void samplingDelay(String title, long start, long end)
    {
        ProfileNode info = getNodeOnly(title);
        info.submit(end - start);
    }

    /**
     * 手动的一个采样测试
     * @param title
     * @param start
     * @param end
     */
    public static void sampling(String title, long start, long end)
    {
        ProfileNode info = getNodeOnly(title);
        info.submit(end - start);
    }

    /**
     * 手动的一个采样测试
     * @param title
     * @param start
     * @param end
     * @param threshold
     */
    public static void sampling(String title, long start, long end, long threshold)
    {
        if (end - start < threshold)
        {
            // 忽略掉太小的
            return;
        }
        ProfileNode info = getNodeOnly(title);
        info.submit(end - start);
    }

    /**
     * 启动一个测试
     * @param title
     */
    public static void start(String title)
    {
        ProfileChildNodeSet nodeSet = session.get();
        if (nodeSet == null)
        {
            session.set(nodeSet = new ProfileChildNodeSet(1000));
        }
        ProfileChildNode info = getNode(title, nodeSet);
        // 象征性的
        sampling(START, 0, 0);
        info.start = System.nanoTime();
    }

    /**
     * 跟进一步(具体的消息则是代码行数)
     */
    public static void step()
    {
        long now = System.nanoTime();
        if (!DEBUG)
        {
            return;
        }
        ProfileChildNodeSet nodeSet = session.get();
        if (nodeSet == null)
        {
            logger.error("一个没有开始的步骤被触发了");
            return;
        }
        ProfileChildNode info = nodeSet.currentNode;
        StackTraceElement ste = new Throwable().getStackTrace()[1];
        String message = " (" + ste.getFileName() + ":" + ste.getLineNumber() + ")";
        long duration = now - info.start;
        info.duration += duration;
        logger.debug(info.title + message + " (us): " + (duration / 1000));
        // 尽可能的避免本地线程的干扰
        info.start = System.nanoTime();
    }

    /**
     * 跟进一步
     * @param message
     */
    public static void step(String message)
    {
        long now = System.nanoTime();
        if (!DEBUG)
        {
            return;
        }
        ProfileChildNodeSet nodeSet = session.get();
        if (nodeSet == null)
        {
            logger.error("一个没有开始的步骤被触发了");
            return;
        }
        ProfileChildNode info = nodeSet.currentNode;
        long duration = now - info.start;
        info.duration += duration;
        logger.debug(info.title + "_" + message + " (us): " + (duration / 1000));
        // 尽可能的避免本地线程的干扰
        info.start = System.nanoTime();
    }

    /**
     * 结束了
     * @param message
     */
    public static void end(String message)
    {
        long now = System.nanoTime();
        ProfileChildNodeSet nodeSet = session.get();
        if (DEBUG)
        {
            if (nodeSet == null)
            {
                sampling(NO_START, now, now);
                throw new Error(String.format("一个没有开始的结束被触发了 %s", message));
            }
            if (!nodeSet.currentNode.title.equals(message))
            {
                throw new Error(String.format("关闭的Profile不匹配 %s => %s", nodeSet.currentNode.title, message));
            }
        }
        else
        {
            if (nodeSet == null)
            {
                sampling(NO_START, now, now);
                logger.error(String.format("一个没有开始的结束被触发了 %s", message));
                return;
            }
            // 不再判断是否匹配了
        }
        ProfileChildNode curInfo = nodeSet.currentNode;
        ProfileChildNode info = curInfo;
        long duration = now - curInfo.start;
        info.source.submit(duration);
        nodeSet.revert(info);
        // 象征性的
        sampling(END, now, System.nanoTime());
    }

    /**
     * 包装了一下本地版本的Logger设置,方便编码
     */
    public static void localDebug()
    {
        DEBUG = true;
        logger.addAppender(new ConsoleAppender(new PatternLayout("%m%n")));
        logger.setLevel(Level.DEBUG);
    }

}

/**
 * 一部分调试统计信息
 * <p>
 * detailed comment
 * @author zhangming.luo 2013-3-20
 * @see
 * @since 1.0
 */
class ProfileNode
{

    final public String title;

    /**
     * 最大执行时间
     */
    public long max = 0;

    /**
     * 最小执行时间
     */
    public long min = Long.MAX_VALUE;

    /**
     * 执行时间<1ms的次数
     */
    final public AtomicLong ucnt = new AtomicLong();

    /**
     * 执行时间<1ms的总时间
     */
    final public AtomicLong usum = new AtomicLong();

    /**
     * 总次数
     */
    final public AtomicLong cnt = new AtomicLong();

    /**
     * 总时间
     */
    final public AtomicLong sum = new AtomicLong();

    public ProfileNode(String title)
    {
        this.title = title;
    }

    public boolean has1ms()
    {
        return cnt.get() > ucnt.get();
    }

    /**
     * 提交一次数据
     * @param duration
     */
    public void submit(long duration)
    {
        sum.addAndGet(duration);
        cnt.getAndIncrement();
        if (duration < min)
        {
            min = duration;
        }
        if (duration > max)
        {
            max = duration;
        }
        if (duration < 1000000)
        {
            ucnt.incrementAndGet();
            usum.addAndGet(duration);
        }
    }

    public void submit(ProfileChildNode node)
    {
        long duration = node.duration;
        sum.addAndGet(duration);
        cnt.getAndIncrement();
        if (duration < min)
        {
            min = duration;
        }
        if (duration > max)
        {
            max = duration;
        }
        if (duration < 1000000)
        {
            ucnt.incrementAndGet();
            usum.addAndGet(duration);
        }
    }

    public void clean()
    {
        min = 0;
        max = 0;
        cnt.set(0);
        sum.set(0);
        ucnt.set(0);
        usum.set(0);
    }

    public long avg()
    {
        if (cnt.get() == 0)
        {
            return 0;
        }
        return (long) (sum.get() / cnt.get());
    }

    public long ravg()
    {
        if (cnt.get() == 0)
        {
            return 0;
        }
        if (cnt.get() == ucnt.get())
        {
            return 0;
        }
        return (long) ((sum.get() - usum.get()) / (cnt.get() - ucnt.get()));
    }

    public ProfileNode clone()
    {
        ProfileNode node = new ProfileNode(title);
        node.cnt.set(cnt.get());
        node.sum.set(sum.get());
        node.ucnt.set(ucnt.get());
        node.usum.set(usum.get());
        node.max = max;
        node.min = min;
        return node;
    }
}

class ProfileChildNodeSet
{
    public ProfileChildNode currentNode;

    private int curIndex = 0;

    private ProfileChildNode pool[];

    private int limit;

    public ProfileChildNodeSet(int maxSize)
    {
        if (maxSize < 10)
        {
            throw new Error("尺寸太小了不能工作");
        }
        this.limit = maxSize - 1;
        pool = new ProfileChildNode[maxSize];
        pool[0] = ProfileChildNode.RESERVE_NODE;
        pool[1] = new ProfileChildNode("unuse");
        pool[1].level = 0;
        for (int i = 1; i < 1000; i++)
        {
            pool[i] = new ProfileChildNode("unuse");
            pool[i].level = i;
            pool[i].parent = pool[i - 1];
        }
    }

    public void revert(ProfileChildNode info)
    {
        // 由于有一个保留的在0号位上所以可以省去这次判断
        currentNode = pool[--curIndex];
    }

    public ProfileChildNode getNode(String title)
    {
        if (curIndex == limit)
        {
            Profiles.sampling(Profiles.TOO_MANY_LEVEL, 0, 0);
            return ProfileChildNode.RESERVE_NODE;
        }
        currentNode = pool[++curIndex];
        currentNode.title = title;
        return currentNode;
    }
}

class ProfileChildNode
{

    public static final ProfileChildNode RESERVE_NODE = new ProfileChildNode("出错时专用的");

    public ProfileNode source;

    public String title;

    /**
     * 父节点
     */
    public ProfileChildNode parent;

    public long start;

    public long duration;

    public ProfileChildNode(String title)
    {
        this.title = title;
    }

    /**
     * 单纯的重置
     */
    public void reset()
    {
        start = 0;
        duration = 0;
    }

    public int level = -1;

}