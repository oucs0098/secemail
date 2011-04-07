package openpgp.keystore.exceptions;

/**
 * <p>A general exception raised by classes when signature verification 
 * has problems.</p>
 */
public class VerificationException extends Exception {
	
	/** Creates a new instance of VerificationException */
    public VerificationException(String message) {
        super(message);
    }
    
}
