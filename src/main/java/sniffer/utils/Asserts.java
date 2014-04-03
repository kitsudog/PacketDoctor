package sniffer.utils;

public class Asserts
{

    public static void isNull(Object... objects)
    {
        for (Object obj : objects)
        {
            if (obj != null)
            {
                throw new RuntimeException("断言出现错误");
            }
        }
    }

    public static void isTrue(boolean b)
    {
        isTrue("断言出现错误", b);
    }

    public static void isTrue(String msg, boolean b)
    {
        if (!b)
        {
            throw new RuntimeException(msg);
        }
    }

    public static void isNotNull(Object... objects)
    {
        for (Object obj : objects)
        {
            if (obj == null)
            {
                throw new RuntimeException("断言出现错误");
            }
        }
    }

    public static void isEquals(Object orig, Object... objects)
    {
        if (orig == null)
        {
            for (Object obj : objects)
            {
                if (obj != null)
                {
                    throw new RuntimeException("断言出现错误");
                }
            }
        }
        else
        {
            for (Object obj : objects)
            {
                if (orig.equals(obj))
                {
                    throw new RuntimeException("断言出现错误");
                }
            }
        }
    }

}
