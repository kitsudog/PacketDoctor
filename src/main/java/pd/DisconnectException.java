package pd;

/**
 * 断线终止了
 * <p>
 * @author zhangming.luo 2014年4月4日
 * @see
 * @since 1.0
 */
public class DisconnectException extends HandlerException
{

    /**
     * 
     */
    private static final long serialVersionUID = 6944900576477077403L;

    public String msg;

    public DisconnectException(String msg)
    {
        this.msg = msg;
    }

}
