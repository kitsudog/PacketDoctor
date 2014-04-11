package pd.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

public class EndlessFileInputStream extends FileInputStream
{

    public EndlessFileInputStream(File file) throws FileNotFoundException
    {
        super(file);
    }

    @Override
    public int read() throws IOException
    {
        int b;
        while ((b = super.read()) < 0)
        {
            // 文件到结尾了
            try
            {
                Thread.sleep(100);
            }
            catch (InterruptedException e)
            {
                e.printStackTrace();
            }
        }
        return b;
    }

    @Override
    public int read(byte[] b) throws IOException
    {
        int cnt;
        while ((cnt = super.read(b)) < 0)
        {
            // 文件到结尾了
            try
            {
                Thread.sleep(100);
            }
            catch (InterruptedException e)
            {
                e.printStackTrace();
            }
        }
        return cnt;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException
    {
        int cnt;
        while ((cnt = super.read(b, off, len)) < 0)
        {
            // 文件到结尾了
            try
            {
                Thread.sleep(100);
            }
            catch (InterruptedException e)
            {
                e.printStackTrace();
            }
        }
        return cnt;
    }
}
