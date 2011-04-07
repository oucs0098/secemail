package openpgp.keystore.model.keyhandlers;

import java.io.File;
import core.exceptions.ChecksumFailureException;
import core.exceptions.KeyHandlerException;
import core.keyhandlers.KeyHandlerParameters;
import core.keyhandlers.KeyIdentifier;
import core.keyhandlers.KeyObject;
import openpgp.keystore.KeyParser;

/** Key handler dealing with a file containing ascii-encoded public key(s)
 * @version $Id: OpenPGPAsciiPublicKeyFile.java,v 1.5 2007-08-28 09:46:28 nigelb Exp $
 */
public class OpenPGPAsciiPublicKeyFile extends OpenPGPAsciiKeyFile {

    /** <p>Constructor for the ascii public key file.</p> */
    public OpenPGPAsciiPublicKeyFile() {
        super();
        description = "OpenPGP ASCII Public Key File";
    }
    
	/** <p>Constructor for this ascii public key file.</p>
	 * <p>The object methods can append to it accordingly.</p>
	 * @param targetFile The file to which the byte stream should be directed
	 */
	public OpenPGPAsciiPublicKeyFile(File targetFile, KeyParser keyParser) {
		super(targetFile, keyParser);
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
