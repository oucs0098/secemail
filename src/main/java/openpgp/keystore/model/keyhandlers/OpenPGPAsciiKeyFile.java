package openpgp.keystore.model.keyhandlers;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Iterator;

import openpgp.keystore.*;
import openpgp.keystore.model.*;
import openpgp.keystore.util.*;
import core.algorithmhandlers.openpgp.util.Armory;
import core.exceptions.AlgorithmException;
import core.exceptions.ChecksumFailureException;
import core.exceptions.KeyHandlerException;
import core.keyhandlers.KeyHandlerParameters;
import core.keyhandlers.KeyIdentifier;
import core.keyhandlers.KeyObject;

/** <p>Class representing an OpenPGP ASCII file (*.asc).</p> 
 * @version $Id: OpenPGPAsciiKeyFile.java,v 1.6 2007-08-28 09:44:26 nigelb Exp $
 */
public class OpenPGPAsciiKeyFile extends OpenPGPKeyFile {
    
    /** <p>Constructor for this ascii file.</p> */
	public OpenPGPAsciiKeyFile() {
        this(null, new KeyParser());
	}
	
	/** <p>Constructor for this ascii export file.</p>
	 * <p>The object methods can append to it accordingly.</p>
	 * @param targetFile The file to which the byte stream should be directed
	 * @param keyParser the key parser to use for reading  in keys
	 */
	public OpenPGPAsciiKeyFile(File targetFile, KeyParser keyParser) {
		super(targetFile, keyParser);
		description = "OpenPGP ASCII File";
	}
	
	/** Method to return the key block header for an ascii armored key block
	 * @param isPrivate Whether the key block is a private key block (if not, 
	 * it's public)
	 * @return The header byte stream
	 * @throws IOException
	 */
	private byte[] getKeyBlockHeader(boolean isPrivate) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		baos.write(getKeyBlockHeaderLine(isPrivate).getBytes());
		baos.write("Version: Secure Email Proxy v".getBytes()); 
		baos.write(core.CoreVersionInfo.version.getBytes()); 
        baos.write("\r\n".getBytes());
        baos.write("Comment: Oxford Brookes Secure Email Project (".getBytes());
        baos.write(core.CoreVersionInfo.website.getBytes()); 
        baos.write(")\r\n".getBytes());
        baos.write("\r\n".getBytes());
        return baos.toByteArray();
	}
	
	/** Method to return the key block trailer for an ascii armored key block
	 * @param isPrivate Whether the key block is a private key block (if not, 
	 * it's public)
	 * @return The trailer byte stream
	 * @throws IOException
	 */
	private String getKeyBlockTrailerLine(boolean isPrivate) {
		String trailer;
		if (isPrivate) {
			trailer = "-----END PGP PRIVATE KEY BLOCK-----\r\n";
		} else {
			trailer = "-----END PGP PUBLIC KEY BLOCK-----\r\n";
		}
		return trailer;
	}
	
	/** Method to return the key block header for an ascii armored key block
	 * @param isPrivate Whether the key block is a private key block (if not, 
	 * it's public)
	 * @return The trailer byte stream
	 * @throws IOException
	 */
	private String getKeyBlockHeaderLine(boolean isPrivate) {
		String header;
		if (isPrivate) {
			header = "-----BEGIN PGP PRIVATE KEY BLOCK-----\r\n";
		} else {
			header = "-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n";
		}
		return header;
	}
	
	/** <p>Method to export a single public certificate, the primary signing 
	 * key with all existing exportable user IDs, exportable signatures, and 
	 * public subkeys.</p>
	 * @param key The certificate to export
	 * @param append Whether to append to the file or overwrite the current file
	 */
	public void exportPublicCertificate(PrimarySigningKey key, boolean append)
			throws IOException, KeyHandlerException {
		// clobber the file
		clear();
        // open the file writing stream
        FileOutputStream fout = new FileOutputStream(
        		externalFile.getAbsolutePath(), append);
        // write ascii header
        fout.write(getKeyBlockHeader(false));
        // write key in ascii armored format
        fout.write(Armory.armor(
        		getPublicKeyData(key, false)).getBytes());
        // write ascii trailer
        fout.write(getKeyBlockTrailerLine(false).getBytes());
        // close the stream
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
		// clobber the file
		clear();
        // open the file writing stream
        FileOutputStream fout = new FileOutputStream(
        		externalFile.getAbsolutePath(), append);
        // write ascii header
        fout.write(getKeyBlockHeader(true));
        // write key in ascii armored format
        fout.write(Armory.armor(
        		getPrivateKeyData(key, false)).getBytes());
        // write ascii trailer
        fout.write(getKeyBlockTrailerLine(true).getBytes());
        // close the stream
        fout.close();
	}
	
	/** <p>Method to export an entire public keyring, all certificates, each
	 * containing the primary signing keys with all existing exportable 
	 * user IDs, exportable signatures, and public subkeys - but no trust
	 * packets.</p>
	 * NOTE: This method will always try to overwrite the file
	 * @param keyStore The keyring to export
	 */
	public void exportPublicKeyring(KeyStore keyStore)
			throws IOException, KeyHandlerException {
		// clobber the file
		clear();
        // open the file writing stream
        FileOutputStream fout = new FileOutputStream(
        		externalFile.getAbsolutePath(), false);
        // write ascii header
        fout.write(getKeyBlockHeader(false));
        // collect all the keys together
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        for (Iterator it = keyStore.getAllKeysIterator(); it.hasNext();) {
        	PrimarySigningKey primaryKey = (PrimarySigningKey)it.next();
        	if (primaryKey.hasPublicKeyPart()) {
        		baos.write(getPublicKeyData(primaryKey, false));
        	}
        }
        // write collected public keyring in ascii armored format
        fout.write(Armory.armor(baos.toByteArray()).getBytes());
        // write ascii trailer
        fout.write(getKeyBlockTrailerLine(false).getBytes());
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
		// clobber the file
		clear();
        // open the file writing stream
        FileOutputStream fout = new FileOutputStream(
        		externalFile.getAbsolutePath(), false);
        // write ascii header
        fout.write(getKeyBlockHeader(true));
        // collect all the keys together
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        for (Iterator it = keyStore.getAllKeysIterator(); it.hasNext();) {
        	PrimarySigningKey primaryKey = (PrimarySigningKey)it.next();
        	if (primaryKey.hasPrivateKeyPart()) {
        		baos.write(getPrivateKeyData(primaryKey, false));
        	}
        }
        // write collected public keyring in ascii armored format
        fout.write(Armory.armor(baos.toByteArray()).getBytes());
        // write ascii trailer
        fout.write(getKeyBlockTrailerLine(true).getBytes());
        // close the streams
        baos.close();
        fout.close();
	}
	
	/** Method to read public keys from the OpenPGP ASCII file
	 * @return a keyring object containing public keys
	 */
    public KeyStore readPublicKeys() throws IOException, KeyHandlerException {
    	return readKeys(false);
    }
    
    /** Method to read private keys from the OpenPGP ASCII file
	 * @return a keyring object containing private keys
	 */
    public KeyStore readPrivateKeys() throws IOException, KeyHandlerException {
    	return readKeys(true);
    }
    
    /** Method to read keys from an ASCII file. The file should either include a
     * private key block or a public key block, and the parameter should be set
     * or unset accordingly. 
     * @param readPrivate Whether to expect a private key block or not (if not,
     * a public key block is expected
     * @return A key store object containing the decoded keys
     * @throws IOException In case of IO problems
     * @throws KeyHandlerException In case of other problems
     */
    private KeyStore readKeys(boolean readPrivate) throws IOException,
			KeyHandlerException {
    	// set up the header and trailer strings
    	String header = getKeyBlockHeaderLine(readPrivate).trim();
    	String trailer = getKeyBlockTrailerLine(readPrivate).trim();
    	// process the file
    	try {
        	FileInputStream stream = new FileInputStream(externalFile);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            
            // read and decode ascii file
            String line = null;
            do {
                line = StreamHelper.readLine(stream);

                // read until header
                if (line!=null) {
                    if (line.compareTo(header)==0) {

                        ByteArrayOutputStream tmp = new ByteArrayOutputStream();

                        // read until blank line
                        line = StreamHelper.readLine(stream);
                        while ((line!=null) && (line.length()>0))
                            line = StreamHelper.readLine(stream);

                        // read body
                        line = StreamHelper.readLine(stream);
                        while ((line!=null) && (line.compareTo(trailer)!=0)) {
                            tmp.write(line.getBytes()); 
                            tmp.write("\r\n".getBytes());
                            line = StreamHelper.readLine(stream);
                        }

                        // Process key data
                        if (line.compareTo(trailer)==0) {
                            out.write(Armory.disarm(
                            		new String(tmp.toString())));
                        } else {
                            throw new AlgorithmException(
                            		"ASCII key file is incomplete.");
                        }
                    }
                }

            } while (line!=null);
            
            stream.close();
            
            // delegate decoding to the keyring parser
            if (readPrivate) {
            	return keyParser.getKeyStore(new byte[0], out.toByteArray());
            } else {
            	return keyParser.getKeyStore(out.toByteArray(), new byte[0]);
            }
            
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