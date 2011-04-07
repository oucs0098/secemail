package openpgp.keystore.exceptions;

/**
 * <p>An exception raised by the keymanager class if the keyring structure
 * is not as expected.</p>
 */
public class KeyringStructureException extends Exception {

	/** Creates a new instance of KeyringStructureException */
    public KeyringStructureException(String message) {
        super(message);
    }
    
}
