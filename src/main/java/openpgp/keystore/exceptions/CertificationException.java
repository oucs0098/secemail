package openpgp.keystore.exceptions;

/**
 * <p>A general exception raised by a primary key when certification of a 
 * user binding has problems.</p>
 */
public class CertificationException extends Exception {

	/** Creates a new instance of CertificationException */
    public CertificationException(String message) {
        super(message);
    }
    
}
