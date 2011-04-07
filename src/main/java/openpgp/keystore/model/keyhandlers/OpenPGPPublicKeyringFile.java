package openpgp.keystore.model.keyhandlers;

import java.io.File;
import core.exceptions.ChecksumFailureException;
import core.exceptions.KeyHandlerException;
import core.keyhandlers.KeyHandlerParameters;
import core.keyhandlers.KeyIdentifier;
import core.keyhandlers.KeyObject;
import openpgp.keystore.KeyParser;

/** Key handler dealing with a file containing binary-encoded public key(s)
 * @version $Id: OpenPGPPublicKeyringFile.java,v 1.4 2007-08-28 09:52:43 nigelb Exp $
 */
public class OpenPGPPublicKeyringFile extends OpenPGPBinaryKeyFile {

	/** <p>Constructor for the public keyring file.</p> */
    public OpenPGPPublicKeyringFile() {
        this(null, new KeyParser());
    }
    
    /** <p>Constructor for this public keyring file.</p>
	 * @param targetFile The file to which the byte stream should be directed
	 * @param keyParser The key parser to use for key parsing
	 */
	public OpenPGPPublicKeyringFile(File targetFile, KeyParser keyParser) {
		super(targetFile, keyParser);
		description = "OpenPGP Public Keyring File";
	}
	
	/** @see core.keyhandlers.KeyHandler#findKeys(core.keyhandlers.KeyIdentifier, 
	 * core.keyhandlers.KeyHandlerParameters)
	 */
	public KeyObject[] findKeys(KeyIdentifier id,
			KeyHandlerParameters parameters) throws KeyHandlerException,
			ChecksumFailureException {
		return findKeys(id, false);
	}
	
}
