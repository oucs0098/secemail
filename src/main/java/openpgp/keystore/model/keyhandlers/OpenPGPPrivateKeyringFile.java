package openpgp.keystore.model.keyhandlers;

import java.io.File;
import core.exceptions.ChecksumFailureException;
import core.exceptions.KeyHandlerException;
import core.keyhandlers.KeyHandlerParameters;
import core.keyhandlers.KeyIdentifier;
import core.keyhandlers.KeyObject;
import openpgp.keystore.KeyParser;

/** Key handler dealing with a file containing binary-encoded private key(s)
 * @version $Id: OpenPGPPrivateKeyringFile.java,v 1.5 2007-08-28 09:52:03 nigelb Exp $
 */
public class OpenPGPPrivateKeyringFile extends OpenPGPBinaryKeyFile {

	/** <p>Constructor for the public keyring file.</p> */
    public OpenPGPPrivateKeyringFile() {
    	this(null, new KeyParser());
    }
    
    /** <p>Constructor for this public keyring file.</p>
	 * @param targetFile The file to which the byte stream should be directed
	 * @param keyParser The key parser to use for key parsing
	 */
	public OpenPGPPrivateKeyringFile(File targetFile, KeyParser keyParser) {
		super(targetFile, keyParser);
		description = "OpenPGP Private Keyring File";
	}
	
	/** @see core.keyhandlers.KeyHandler#findKeys(core.keyhandlers.KeyIdentifier,
	 * core.keyhandlers.KeyHandlerParameters)
	 */
	public KeyObject[] findKeys(KeyIdentifier id,
			KeyHandlerParameters parameters) throws KeyHandlerException,
			ChecksumFailureException {
		return findKeys(id, true);
	}
	
}
