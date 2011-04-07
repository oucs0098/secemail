package openpgp.keystore.model.keyhandlers;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.util.Iterator;
import java.util.List;

import openpgp.keystore.KeyParser;
import openpgp.keystore.model.KeyStore;
import openpgp.keystore.model.PrimarySigningKey;
import openpgp.keystore.model.Signature;
import openpgp.keystore.model.Subkey;
import openpgp.keystore.model.UserID;
import openpgp.keystore.model.UserAttribute;
import openpgp.keystore.util.*;
import core.keyhandlers.KeyFile;
import core.keyhandlers.KeyObject;
import core.keyhandlers.KeyHandlerParameters;
import core.keyhandlers.KeyIdentifier;
import core.algorithmhandlers.openpgp.OpenPGPPacketOutputStream;
import core.exceptions.KeyHandlerException;

/** Abstract class representing an OpenPGP export file. The methods defined in
 * the OpenPGPFileExporter interface should be implemented by the extending
 * class.
 * @version $Id: OpenPGPKeyFile.java,v 1.5 2007-08-28 09:50:50 nigelb Exp $
 */
public abstract class OpenPGPKeyFile extends KeyFile implements
		OpenPGPKeyExporter {

	/** The file to which packets will be exported, or from which packets will
	 * be imported.
	 */
	protected File externalFile;
	
	/** The keyring parser, used for key data input parsing */
	protected KeyParser keyParser;
	
	/** A textual description of this object */
	protected String description;
        
	/** <p>Constructor for this ascii export file.</p>
	 */
	protected OpenPGPKeyFile() {
		super();
	}
	
	/** <p>Constructor for this ascii export file.</p>
	 * @param targetFile The source/target for the byte stream
	 */
	protected OpenPGPKeyFile(File targetFile, KeyParser keyParser) {
		this();
        if (targetFile != null) {
        	externalFile = targetFile;
        	setFile(externalFile.getAbsolutePath());
        }
        this.keyParser = keyParser;
	}
	
	/** Method to clobber the file */
	protected void clear() {
		externalFile.delete();
	}
        
    /**
     * <p>Set the file to use with no parameters.</p>
     * <p>This overrides the superclass method of the same name.</p>
     * @param filename The path and filename of the key store.
     */
    public void setFile(String filename) {
        super.setFile(filename);
        externalFile = new File(filename);
    }
    
    /** <p>Set the file to use.</p>
     * <p>This method points the key handler at a given file. It does not 
     * actually open the file, this should be done by the appropriate search
     * method implementations.</p>
     * @param filename The path and filename of the key store.
     * @param parameters Any extra parameters needed (for example a pass 
     * phrase), may be null.
     */
    public void setFile(String filename, KeyHandlerParameters parameters) {
    	super.setFile(filename, parameters);
    	externalFile = new File(filename);
    }
    
    /** <p>Override toString to allow the Key handler to be rendered nicely
     * in a swing list box.</p>
     */
    public String toString() {
        return getDescription() + " (" + 
        		StringHelper.reduceWinPath(getFileName()) + ")";
    }
    
    /** <p>Method to import OpenPGP public keys from a key resource</p>
	 */
    public abstract KeyStore readPublicKeys()
			throws IOException, KeyHandlerException;
    
    /** <p>Method to import OpenPGP secret keys from a key resource</p>
	 */
    public abstract KeyStore readPrivateKeys()
			throws IOException, KeyHandlerException;
    
    /** Method to find matching keys from a given KeyIdentifier object
	 * @param id The search parameters
	 * @param inPrivateKeys Whether to search amongst the private keys, or
	 * if false, amongst the public keys
	 * @return An array of matching keys
	 */
	protected KeyObject[] findKeys(KeyIdentifier id, boolean inPrivateKeys)
			throws KeyHandlerException {
		try {
			KeyStore keyStore = null;
			if (inPrivateKeys) {
				keyStore = readPrivateKeys();
			} else {
				keyStore = readPublicKeys();
			}
			List keyList = keyStore.findPrimaryKeys(id);
			// not sure why calling toArray() on keyList and casting to
			// KeyObject[] does not work (class cast exception)
			int numElements = 0;
			if (keyList != null) numElements = keyList.size();
			KeyObject[] keys = new KeyObject[numElements];
			for (int i = 0; i < numElements; ++i) {
				keys[i] = (PrimarySigningKey)keyList.get(i);
			}
			return keys;
		} catch(Exception e) {
			throw new KeyHandlerException(e.getMessage());
		}
	}
	
	/** <p>Method to translate a single private certificate, the public primary 
	 * signing key with all existing exportable user IDs, signatures, and
	 * private subkeys, into a byte array.</p>
	 * <p>NOTE: All trust packets and non-exportable (local) signatures are 
	 * ignored for export to an ascii file</p>
	 * @param key The certificate to export
	 * @param includeLocal Whether to include trust packets and other local 
	 * packets (e.g. local signatures) in the byte stream, e.g. for local 
	 * keyrings
	 * @return The array of bytes representing the certificate
	 */
	protected byte[] getPrivateKeyData(PrimarySigningKey key,
			boolean includeLocal) throws KeyHandlerException {
		try {
	        // create / append key file
	        ByteArrayOutputStream baos = new ByteArrayOutputStream();
	        OpenPGPPacketOutputStream pos = new OpenPGPPacketOutputStream(baos);
	        
	        // write the key packet
	        key.writePrivateKeyringPacket(pos, includeLocal);
	        if (key.isRevoked()) {  // possible revocation self-signature (0x20)
	        	Signature revocationSignature = key.getRevocationSignature();
				revocationSignature.writePrivateKeyringPacket(pos, includeLocal);
			}
	        
	        // write any direct key signatures
	        Iterator it = key.getSignatureIterator();
        	while (it.hasNext()) {
        		Signature signature = (Signature)it.next();
        		if (includeLocal || signature.isExportable()) {
        			signature.writePrivateKeyringPacket(pos, includeLocal);
        			if (signature.isRevoked()) {
	        			Signature rsig = signature.getRevocationSignature();
	        			rsig.writePrivateKeyringPacket(pos, includeLocal);
	        		}
        		}
        	}
	        
	        // write associated user id packets and their signature packets
	        Iterator ubit = key.getUserIDIterator();
	        while (ubit.hasNext()) {
	        	UserID userID = (UserID)ubit.next();
	        	userID.writePrivateKeyringPacket(pos, includeLocal);
	        	
	        	Iterator sigit = userID.getSignatureIterator();
	        	while (sigit.hasNext()) {
	        		Signature signature = (Signature)sigit.next();
	        		if (includeLocal || signature.isExportable()) {
	        			signature.writePrivateKeyringPacket(pos, includeLocal);
	        			if (signature.isRevoked()) {
		        			Signature rsig = signature.getRevocationSignature();
		        			rsig.writePrivateKeyringPacket(pos, includeLocal);
		        		}
	        		}
	        	}
	        }
	        
	        // write associated user attribute packets and their signature packets
	        Iterator uait = key.getUserAttributeIterator();
	        while (uait.hasNext()) {
	        	UserAttribute userAttribute = (UserAttribute)uait.next();
	        	userAttribute.writePrivateKeyringPacket(pos, includeLocal);
	        	
	        	Iterator sigit = userAttribute.getSignatureIterator();
	        	while (sigit.hasNext()) {
	        		Signature signature = (Signature)sigit.next();
	        		if (includeLocal || signature.isExportable()) {
	        			signature.writePrivateKeyringPacket(pos, includeLocal);
	        			if (signature.isRevoked()) {
		        			Signature rsig = signature.getRevocationSignature();
		        			rsig.writePrivateKeyringPacket(pos, includeLocal);
		        		}
	        		}
	        	}
	        }
	        
	        // write associated subkeys and their signature packets
	        Iterator subkeyIterator = key.getSubkeyIterator(); 
	        while (subkeyIterator.hasNext()) {
	        	Subkey subkey = (Subkey)subkeyIterator.next();
	        	subkey.writePrivateKeyringPacket(pos, includeLocal);
	        	
	        	Iterator sigit = subkey.getSignatureIterator();
	        	if (sigit.hasNext()) {
	        		// there should be only one signature attached to a subkey
	        		// that is the subkey binding signature (0x18)
	        		Signature signature = (Signature)sigit.next();
        			signature.writePrivateKeyringPacket(pos, includeLocal);
        			// revocation signature (0x28) revoking the subkey binding 
        			// signature (0x18) is stored in the subkey itself
        			if (subkey.isRevoked()) {
    	        		Signature rsig = subkey.getRevocationSignature();
            			rsig.writePrivateKeyringPacket(pos, includeLocal);
    	        	}
	        	}
	        	if (sigit.hasNext()) {
	        		System.err.println("ERROR: Subkey has multiple signatures");
	        	}
	        }
	        pos.close();  // close stream
            return baos.toByteArray();
	        
		} catch(Exception e) {
			e.printStackTrace();
			throw new KeyHandlerException(e.getMessage());
		}
	}
	
	/** <p>Method to translate a single public certificate, the public primary 
	 * signing key with all existing exportable user IDs, signatures, and 
	 * public subkeys, into a byte array.</p>
	 * <p>NOTE: All trust packets and non-exportable (local) signatures are 
	 * ignored or included dependent on the 'includeTrust' flag.</p>
	 * @param key The certificate to export
	 * @param includeLocal Whether to include trust packets and other local 
	 * packets (e.g. local signatures) in the byte stream, e.g. for local 
	 * keyrings
	 * @return The array of bytes representing the certificate
	 */
	public static byte[] getPublicKeyData(PrimarySigningKey key,
			boolean includeLocal) throws KeyHandlerException {
		try {
	        // create / append key file
	        ByteArrayOutputStream baos = new ByteArrayOutputStream();
	        OpenPGPPacketOutputStream pos = new OpenPGPPacketOutputStream(baos);
	        
	        // write key packet
	        key.writePublicKeyringPacket(pos, includeLocal);
	        if (key.isRevoked()) {  // possible revocation self-signature (0x20)
	        	Signature revocationSignature = key.getRevocationSignature();
				revocationSignature.writePublicKeyringPacket(pos, includeLocal);
			}
	        
	        // write any direct key signatures
	        Iterator it = key.getSignatureIterator();
        	while (it.hasNext()) {
        		Signature signature = (Signature)it.next();
        		if (includeLocal || signature.isExportable()) {
        			signature.writePublicKeyringPacket(pos, includeLocal);
        			if (signature.isRevoked()) {
	        			Signature rsig = signature.getRevocationSignature();
	        			rsig.writePublicKeyringPacket(pos, includeLocal);
	        		}
        		}
        	}
	        
	        // write associated user id packets and their signature packets
	        Iterator uit = key.getUserIDIterator();
	        while (uit.hasNext()) {
	        	UserID userID = (UserID)uit.next();
	        	userID.writePublicKeyringPacket(pos, includeLocal);
	        	
	        	Iterator sigit = userID.getSignatureIterator();
	        	while (sigit.hasNext()) {
	        		Signature signature = (Signature)sigit.next();
	        		if (includeLocal || signature.isExportable()) {
	        			signature.writePublicKeyringPacket(pos, includeLocal);
	        			if (signature.isRevoked()) {
		        			Signature rsig = signature.getRevocationSignature();
		        			rsig.writePublicKeyringPacket(pos, includeLocal);
		        		}
	        		}
	        	}
	        }
	        
	        // write associated user attribute packets and their signature packets
	        Iterator uait = key.getUserAttributeIterator();
	        while (uait.hasNext()) {
	        	UserAttribute userAttribute = (UserAttribute)uait.next();
	        	userAttribute.writePrivateKeyringPacket(pos, includeLocal);
	        	
	        	Iterator sigit = userAttribute.getSignatureIterator();
	        	while (sigit.hasNext()) {
	        		Signature signature = (Signature)sigit.next();
	        		if (includeLocal || signature.isExportable()) {
	        			signature.writePrivateKeyringPacket(pos, includeLocal);
	        			if (signature.isRevoked()) {
		        			Signature rsig = signature.getRevocationSignature();
		        			rsig.writePrivateKeyringPacket(pos, includeLocal);
		        		}
	        		}
	        	}
	        }
	        
	        // write associated subkeys and their signature packets
	        Iterator subkeyIterator = key.getSubkeyIterator();
	        while (subkeyIterator.hasNext()) {
	        	Subkey subkey = (Subkey)subkeyIterator.next();
	        	subkey.writePublicKeyringPacket(pos, includeLocal);
	        	
	        	Iterator sigit = subkey.getSignatureIterator();
	        	if (sigit.hasNext()) {
	        		// there should be only one signature attached to a subkey
	        		// that is the subkey binding signature (0x18)
	        		Signature signature = (Signature)sigit.next();
        			signature.writePublicKeyringPacket(pos, includeLocal);
        			// revocation signature (0x28) revoking the subkey binding 
        			// signature (0x18) is stored in the subkey itself
        			if (subkey.isRevoked()) {
    	        		Signature rsig = subkey.getRevocationSignature();
            			rsig.writePublicKeyringPacket(pos, includeLocal);
    	        	}
	        	}
	        	if (sigit.hasNext()) {
	        		System.err.println("ERROR: Subkey has multiple signatures");
	        	}
	        }
	        pos.close();  // close stream
            return baos.toByteArray();
	        
		} catch(Exception e) {
			e.printStackTrace();
			throw new KeyHandlerException(e.getMessage());
		}
	}

	/** Unsupported
	 * @see core.keyhandlers.KeyHandler#changeSetting(
	 * core.keyhandlers.KeyHandlerParameters)
	 */
	public void changeSetting(KeyHandlerParameters parameters)
			throws KeyHandlerException {
	}

	/** Unsupported
	 * @see core.keyhandlers.KeyHandler#removeKeys(
	 * core.keyhandlers.KeyIdentifier, 
	 * core.keyhandlers.KeyHandlerParameters)
	 */
	public int removeKeys(KeyIdentifier id, KeyHandlerParameters parameters)
			throws KeyHandlerException {
		return 0;
	}
	
	/** @see core.keyhandlers.KeyHandler#getDescription()
	 */
	public String getDescription() {
		return description;
	}

}
