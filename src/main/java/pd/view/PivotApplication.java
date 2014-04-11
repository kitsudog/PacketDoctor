package pd.view;

import java.awt.Font;

import org.apache.pivot.beans.BXMLSerializer;
import org.apache.pivot.collections.Map;
import org.apache.pivot.wtk.Application;
import org.apache.pivot.wtk.Display;
import org.apache.pivot.wtk.Theme;
import org.apache.pivot.wtk.Window;

public class PivotApplication implements Application
{

    public static Window window;

    @Override
    public void startup(Display display, Map<String, String> properties) throws Exception
    {
        // 此处要使用等宽字体比较好
        Theme.getTheme().setFont(new Font("新宋体", Font.PLAIN, 12));
        BXMLSerializer bxmlSerializer = new BXMLSerializer();
        window = (Window) bxmlSerializer.readObject(GUIView.class, "/pd/window.bxml");
        window.open(display);
    }

    @Override
    public boolean shutdown(boolean optional) throws Exception
    {
        window.close();
        return false;
    }

    @Override
    public void suspend() throws Exception
    {
        // TODO Auto-generated method stub

    }

    @Override
    public void resume() throws Exception
    {
        // TODO Auto-generated method stub

    }

}
