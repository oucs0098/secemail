package openpgp.keystore.exceptions;

/**
 * <p>A general exception raised by the keymanager key-handling classes.</p> 
 * <p>Also raised when attempting to revoke keyring classes with an incorrect 
 * revocation key.</p>
 */
public class KeyMismatchException extends Exception {

	/** Creates a new instance of KeyMismatchException */
    public KeyMismatchException(String message) {
        super(message);
    }
    
}
