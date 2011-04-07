package openpgp.keystore.exceptions;

/**
 * <p>A general exception raised by a primary key when creation and 
 * certification of a new user ID has problems.</p>
 */
public class UserBindingException extends Exception {

	/** Creates a new instance of UserBindingException */
    public UserBindingException(String message) {
        super(message);
    }
    
}
