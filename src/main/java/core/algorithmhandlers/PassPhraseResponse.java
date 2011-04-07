package core.algorithmhandlers;

/** 
 * interface to help decouple the application from the core classes
 */
public interface PassPhraseResponse {

    /** Abort button pressed. */
    public static final int ABORT = 1;
    /** Send anyway pressed. */
    public static final int SENDANYWAY = 2;
    /** Ok pressed. */
    public static final int OK = 3;
    
    /** Return the response code */
    public int getResponseCode();
    
    /** Return the passphrase entered. */
    public byte[] getPassPhrase();
    
}