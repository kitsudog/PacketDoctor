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
        if (!b)
        {
            throw new RuntimeException("断言出现错误");
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

}
