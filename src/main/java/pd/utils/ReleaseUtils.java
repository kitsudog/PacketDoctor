package pd.utils;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.StringTokenizer;

public class ReleaseUtils
{
    public static void release(String lib) throws Exception
    {
        String libpath = System.getProperty("java.library.path");
        StringTokenizer st = new StringTokenizer(libpath, System.getProperty("path.separator"));

        while (true)
        {
            if (!st.hasMoreTokens())
            {
                throw new Exception("无法释放指定库, 请设置一个拥有写权限的目录-Djava.library.path=");
            }
            String path = st.nextToken();
            String libname = lib.replaceAll(".+/([^/]+)$", "$1");
            File temporaryLib = new File(new File(path), libname);
            try
            {
                if (!temporaryLib.exists())
                {
                    FileOutputStream outputStream = new FileOutputStream(temporaryLib);
                    byte[] array = new byte[8192];
                    InputStream libStream = null;
                    libStream = Class.class.getResourceAsStream(lib);
                    for (int i = libStream.read(array); i != -1; i = libStream.read(array))
                    {
                        outputStream.write(array, 0, i);
                    }
                    outputStream.flush();
                    outputStream.close();
                    libStream.close();
                    break;
                }
                else
                {
                    break;
                }
            }
            catch (Exception e)
            {
                // PASS
            }
        }
    }
}
