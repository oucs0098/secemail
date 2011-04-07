package openpgp.keystore.model.keyhandlers;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Iterator;

import openpgp.keystore.KeyParser;
import openpgp.keystore.model.*;
import core.exceptions.ChecksumFailureException;
import core.exceptions.KeyHandlerException;
import core.keyhandlers.KeyHandlerParameters;
import core.keyhandlers.KeyIdentifier;
import core.keyhandlers.KeyObject;

/** Key handler dealing with a file containing binary-encoded public key(s)
 * @version $Id: OpenPGPBinaryKeyFile.java,v 1.6 2007-08-28 09:48:19 nigelb Exp $
 */
public class OpenPGPBinaryKeyFile extends OpenPGPKeyFile {
        
    /** <p>Constructor for the binary key file.</p> */
    public OpenPGPBinaryKeyFile() {
        this(null, new KeyParser());
    }
	
	/** <p>Constructor for this binary export file.</p>
	 * <p>The object methods can append to it accordingly.</p>
	 * @param targetFile The file to which the byte stream should be directed
	 * @param keyParser the key parser to use for reading  in keys
	 */
	public OpenPGPBinaryKeyFile(File targetFile, KeyParser keyParser) {
		super(targetFile, keyParser);
		description = "OpenPGP Binary File";
	}
	
	/** <p>Method to export a single public certificate, the primary signing 
	 * key with all existing exportable user IDs, exportable signatures, and 
	 * public subkeys.</p>
	 * @param key The certificate to export
	 * @param append Whether to append to the file or overwrite the current file
	 */
	public void exportPublicCertificate(PrimarySigningKey key, boolean append)
			throws IOException, KeyHandlerException {
		// open the file for writing
        FileOutputStream fout = new FileOutputStream(
        		externalFile.getAbsolutePath(), append);
        // write keyring in raw binary OpenPGP format
        fout.write(getPublicKeyData(key, false));
        fout.close();
	}
	
	/** <p>Method to export a single private certificate, the primary signing 
	 * key with all existing exportable user IDs, exportable signatures, and 
	 * private subkeys.</p>
	 * @param key The certificate to export
	 * @param append Whether to append to the file or overwrite the current file
	 */
	public void exportPrivateCertificate(PrimarySigningKey key, boolean append)
			throws IOException, KeyHandlerException {
		// open the file for writing
        FileOutputStream fout = new FileOutputStream(
        		externalFile.getAbsolutePath(), append);
        // write keyring in raw binary OpenPGP format
        fout.write(getPrivateKeyData(key, false));
        fout.close();
	}
	
	/** <p>Method to export an entire public key store, all certificates, each
	 * containing the primary signing keys with all existing exportable 
	 * user IDs, exportable signatures, and public subkeys - but no trust
	 * packets.</p>
	 * NOTE: This method will always try to overwrite the file
	 * @param keyStore The key store to export
	 */
	public void exportPublicKeyring(KeyStore keyStore)
			throws IOException, KeyHandlerException {
        // open the file writing stream
        FileOutputStream fout = new FileOutputStream(
        		externalFile.getAbsolutePath(), false);
        // collect all the keys together
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        for (Iterator it = keyStore.getAllKeysIterator(); it.hasNext();) {
        	PrimarySigningKey primaryKey = (PrimarySigningKey)it.next();
        	if (primaryKey.hasPublicKeyPart()) {
        		baos.write(getPublicKeyData(primaryKey, true));
        	}
        }
        // write collected public keyring in raw binary OpenPGP format
        fout.write(baos.toByteArray());
        // close the streams
        baos.close();
        fout.close();
	}
	
	/** <p>Method to export an entire private keyring, all certificates, each
	 * containing the primary signing key with all existing exportable user IDs,
	 * exportable signatures, and private subkeys - but no trust packets.</p>
	 * NOTE: This method will always try to overwrite the file
	 * @param keyStore The key store to export
	 */
	public void exportPrivateKeyring(KeyStore keyStore)
			throws IOException, KeyHandlerException {
        // open the file writing stream
        FileOutputStream fout = new FileOutputStream(
        		externalFile.getAbsolutePath(), false);
        // collect all the keys together
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        for (Iterator it = keyStore.getAllKeysIterator(); it.hasNext();) {
        	PrimarySigningKey primaryKey = (PrimarySigningKey)it.next();
        	if (primaryKey.hasPrivateKeyPart()) {
        		baos.write(getPrivateKeyData(primaryKey, true));
        	}
        }
        // write collected public keyring in raw binary OpenPGP format
        fout.write(baos.toByteArray());
        // close the streams
        baos.close();
        fout.close();
	}
	
	/** Method to read public keys from the OpenPGP binary file
	 * @return a keyring object containing public keys
	 */
	public KeyStore readPublicKeys() throws IOException, KeyHandlerException {
		try {
            // delegate decoding to the keyring parser
            return keyParser.getKeyStore(externalFile.getAbsolutePath(), null);
        } catch (Exception e) {
            throw new KeyHandlerException(e.getMessage());
        }
	}
	
	/** Method to read secret keys from the OpenPGP binary file
	 * @return a keyring object containing secret keys
	 */
	public KeyStore readPrivateKeys() throws IOException, KeyHandlerException {
		try {
            // delegate decoding to the keyring parser
            return keyParser.getKeyStore(null, externalFile.getAbsolutePath());
        } catch (Exception e) {
            throw new KeyHandlerException(e.getMessage());
        }
	}

	/** @see core.keyhandlers.KeyHandler#addKeys(core.keyhandlers.KeyObject[], 
	 * core.keyhandlers.KeyIdentifier[], core.keyhandlers.KeyHandlerParameters[])
	 */
	public void addKeys(KeyObject[] key, KeyIdentifier[] idDetails, 
			KeyHandlerParameters[] parameters) throws KeyHandlerException {
		// use the export... methods instead.
		throw new UnsupportedOperationException();
	}

	/** @see core.keyhandlers.KeyHandler#findKeys(core.keyhandlers.KeyIdentifier, 
	 * core.keyhandlers.KeyHandlerParameters)
	 */
	public KeyObject[] findKeys(KeyIdentifier id, KeyHandlerParameters parameters) 
	throws KeyHandlerException, ChecksumFailureException {
		// use the subclass findKeys() method instead.
		throw new UnsupportedOperationException();
	}
	
}
