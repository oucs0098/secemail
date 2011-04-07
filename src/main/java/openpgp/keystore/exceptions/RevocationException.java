package openpgp.keystore.exceptions;

/**
 * <p>A general exception raised if a problem with revocation occurs.</p>
 */
public class RevocationException extends Exception {

	/** Creates a new instance of RevocationException */
    public RevocationException(String message) {
        super(message);
    }
    
}
