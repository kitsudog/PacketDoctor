package pd.exception;

public class PassException extends HandlerException
{

    /**
     * 
     */
    private static final long serialVersionUID = 5333549036308462267L;

    final public String msg;

    public PassException(String msg)
    {
        this.msg = msg;
    }
}
