package openpgp.keystore.model.keyhandlers;

import java.io.ByteArrayOutputStream;
import java.io.ByteArrayInputStream;
import openpgp.keystore.KeyParser;
import openpgp.keystore.KeyStoreTrustManager;
import openpgp.keystore.model.KeyStore;
import openpgp.keystore.model.PrimarySigningKey;
import core.algorithmhandlers.openpgp.OpenPGPPacketOutputStream;
import core.algorithmhandlers.openpgp.packets.KeyPacket;
import core.algorithmhandlers.openpgp.packets.PublicSubkeyPacket;
import core.algorithmhandlers.openpgp.packets.SecretSubkeyPacket;
import core.algorithmhandlers.openpgp.packets.SecretKeyPacket;
import core.algorithmhandlers.openpgp.packets.SignaturePacket;
import core.algorithmhandlers.openpgp.packets.TrustPacket;
import core.algorithmhandlers.PassPhrase;
import core.exceptions.KeyHandlerException;
import core.exceptions.AlgorithmException;
import core.keyhandlers.KeyData;
import core.keyhandlers.KeyHandlerParameters;
import core.keyhandlers.KeyIdentifier;
import core.keyhandlers.KeyObject;
import core.keyhandlers.OpenPGPKeyring;
import core.keyhandlers.keydata.OpenPGPKeyData;
import core.keyhandlers.parameters.OpenPGPAddKeyParameters;
import core.keyhandlers.parameters.OpenPGPAddSecretKeyParameters;

/** <p>Class to intercept subkeys, for diversion to a primary signing key.</p>
 * <p>Based on the OpenPGPPublicKeyTrap class, but intended for use in subkey
 * generation, to add one or more subkeys to an existing primary signing
 * key, where the public subkey trap and the secret subkey trap are used 
 * together to capture both public and private subkey data in a separate thread.
 * These classes do not send any data to a real file immediately, preferring to
 * add the subkey to an existing primary signing key in memory, 
 * initialised with fresh trust packets, thereby giving the user the option to 
 * review the new subkey in the in-memory key store before saving to the keyrings
 * in persistent storage (on disk).</p>
 * <p>This mechanism should only be used where new public and secret
 * subkey data is being generated specifically for a given primary signing 
 * key object.</p>
 * @version $Id: OpenPGPPublicSubkeyTrap.java,v 1.5 2007-08-27 21:16:28 nigelb Exp $
 */
public class OpenPGPPublicSubkeyTrap extends OpenPGPKeyring {
	
	/** Public key data data in byte array form, populated by public key trap */
	private byte[] publicKeyData = new byte[0];
	
	/** Secret key data data in byte array form, populated by secret key trap */
	private byte[] secretKeyData = new byte[0];
	
	/** The keyring parser, to use for parsing key data */
	private KeyParser keyParser;
	
	/** The key store to which the keys should be added */
	private KeyStore keyStore;
	
	/** The primary signing key to which the subkeys will be added */
	private PrimarySigningKey psk;
	
	/** The passphrase for the primary signing key (to sign the subkeys) */
	private PassPhrase passPhrase;
	
	/** The trust to apply to the subkeys and their signatures (from the 
	 * primary signing key)
	 */
	private TrustPacket trust;
	
	/** The secret key handler to use in tandem with this when generating a 
	 * new keypair
	 */
	private OpenPGPSecretSubkeyTrap secretSubkeyTrap;
	
	/** Zero-argument constructor */
	public OpenPGPPublicSubkeyTrap(KeyParser keyParser, KeyStore keyStore,
			PrimarySigningKey psk, PassPhrase passPhrase) {
		super();
		this.keyParser = keyParser;
		this.keyStore = keyStore;
		this.psk = psk;
		try {
			this.trust = new TrustPacket(
					new byte[] {(byte)KeyStoreTrustManager.getTrustValue(psk)});
		} catch(AlgorithmException e) {
			this.trust = psk.getTrust();
		}
		this.passPhrase = passPhrase;
		this.secretSubkeyTrap = new OpenPGPSecretSubkeyTrap();
	}
	
	/** Accessor method to get access to the secret key data */ 
	public byte[] toByteArray() {
		return publicKeyData;
	}

	/** <p>Add a number of keys to the key store.</p>
	 * <p>Adds one or more subkeys to an existing key with idDetails ignored and
	 * parameters as necessary.</p>
	 * <p>If a key with the same details already exists it is NOT replaced.</p>
	 * <p>All keys in the array are added to an existing primary signing key
	 * as sub keys.</p>
	 * 
	 * @param key[]
	 *            The keys to store. If key[n] is an instance of OpenPGPKeyData
	 *            then if possible the existing key packet is used. This enables
	 *            you to import keys from other key sources.
	 * @param idDetails[]
	 *            Information identifying the keys. Should be of type
	 *            OpenPGPStandardKeyIdentifier. Must be not null for
	 *            first key.
	 * @param parameters[]
	 *            Any extra parameters needed, for example pass phrases for
	 *            secret key stores etc, may be null.
	 * @throws KeyHandlerException
	 *             if something went wrong.
	 */
	public void addKeys(KeyObject[] key, KeyIdentifier[] idDetails,
			KeyHandlerParameters[] parameters) throws KeyHandlerException {
		try {
			if (!(key instanceof KeyData[])) {
        		throw new KeyHandlerException("Unknown KeyObject type found");
        	}
			
			KeyPacket primaryKeyPacket = psk.getPublicKeyPacket();
			KeyPacket currentKeyPacket = null;
			OpenPGPAddKeyParameters currentParam = null;

			// create / append byte array
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			OpenPGPPacketOutputStream out = new OpenPGPPacketOutputStream(baos);

			// itterate through all given keys, first element is primary
			for (int n = 0; n < key.length; n++) {

				// check initial parameters
				if ((key == null) || (key[n] == null))
					throw new KeyHandlerException("Key material is null.");

				// it is ok for subkeys to have no ID details

				if ((parameters == null) || (parameters[n] == null))
					throw new KeyHandlerException("Key parameter is null.");

				if (!(parameters[n] instanceof OpenPGPAddKeyParameters))
					throw new KeyHandlerException(
							"Key parameter is the wrong type.");

				// create key packet
				currentParam = (OpenPGPAddKeyParameters) parameters[n];

				// this is a subkey
				if (key[n] instanceof OpenPGPKeyData) { 
					// try and import the key packet.
					OpenPGPKeyData tmpKey = (OpenPGPKeyData) key[n];

					if (tmpKey.getKeyPacket() instanceof PublicSubkeyPacket) {
						// key[n] contains a PublicSubkeyPacket
						currentKeyPacket = tmpKey.getKeyPacket(); 
					} else {
						throw new KeyHandlerException("Key "+n+" does " +
								"not appear to be a Public Subkey Packet.");
					}	
				} else {
					currentKeyPacket = new PublicSubkeyPacket(
							currentParam.getCreationDate(), 
							currentParam.getPublicKeyAlgorithm(), 
							key[n].getKeyData().getKey());
				}

				// write key packet
				out.writePacket(currentKeyPacket);
				out.writePacket(trust);
				
				SecretKeyPacket secretKeyPacket = psk.getSecretKeyPacket();
				secretKeyPacket.decryptKeyData(passPhrase.getPassphraseData());

				// sign subkey with primary key
				byte[] tmp = generateSubKeyHashData(
						psk.getPublicKeyPacket().encodePacketBody(), 
						currentKeyPacket.encodePacketBody());

				out.writePacket(new SignaturePacket(generateSubkeySignature(
						secretKeyPacket.getKeyData().getPrivateKey(),
						primaryKeyPacket.getKeyID(),
						currentParam, tmp)));
				out.writePacket(trust);
			}

			// close stream
			out.close();
			publicKeyData = baos.toByteArray();
			baos.close();
			updatePrimarySigningKey();

		} catch (Exception e) {
			e.printStackTrace();
			throw new KeyHandlerException(e.getMessage());
		}
	}

	/** <p>Change a key handler setting.</p>
	 * <p>This method allows you to change a setting of a key handler object, for
	 * example change the passphrase used for unlocking a key.</p>
	 * <p>What settings can be changed depend on the type of key handler.</p>
	 * @param parameters What to change and the parameters needed.
	 * @throws KeyHandlerException if something went wrong.
	 */
	public void changeSetting(KeyHandlerParameters parameters)
			throws KeyHandlerException {
	}
	
	/** Method to update the key store with the new key data */
	private void updatePrimarySigningKey() {
		if (publicKeyData.length > 0 && secretKeyData.length > 0) {
			try {
				keyParser.getSubkeys(psk, 
						new ByteArrayInputStream(publicKeyData),
						new ByteArrayInputStream(secretKeyData));
				keyStore.touch();
			} catch(Exception e) {
				e.printStackTrace();
				System.err.println("Error: " + e.getMessage());
			}
		}
	}
	
	/** @return the secret key trap */
	public OpenPGPSecretSubkeyTrap getSecretSubkeyTrap() {
		return secretSubkeyTrap;
	}

	/** Method to return a readable description of this object
     * @return A readable description of this object
     */
    public String getDescription() {
    	return "OpenPGP Public Subkey Trap";
    }
    
    /**
	 * Inner class to trap secret keys, for diversion to a keyring in memory.
	 * Based on OpenPGPSecretKeyring, although this does not send any data to a
	 * real file, preferring to update a keyring with the data, via the outer 
	 * class, giving the user the option to change details about the key in the
	 * keyring before saving to the keyrings.
	 */
	private class OpenPGPSecretSubkeyTrap extends OpenPGPKeyring {
		
		/** Accessor method to get access to the secret key data */ 
		public byte[] toByteArray() {
			return OpenPGPPublicSubkeyTrap.this.secretKeyData;
		}
		
		/** <p>Add a number of keys to an internal key cache.</p>
		 * <p>Stores a key in the key store with details specified by idDetails 
		 * and parameters as necessary. Note that it will clobber anything 
		 * already in the cache each time this method is called.</p>
		 * <p>If a key with the same details already exists it is NOT 
		 * replaced.</p><p>The first key in the array is added as a primary
		 * key (which must be capable of signing), all other keys are added as
		 * sub keys.</p>
		 * 
		 * @param key[]
		 *            The keys to store. If key[n] is an instance of
		 *            OpenPGPKeyData then if possible the existing key packet is
		 *            used. This enables you to import keys from other key
		 *            sources.
		 * @param idDetails[]
		 *            Information identifying the keys. Should be of type
		 *            OpenPGPStandardKeyIdentifier. Must be not null for primary
		 *            (first) key.
		 * @param parameters[]
		 *            Any extra parameters needed, for example pass phrases for
		 *            secret key stores etc, may be null.
		 * @throws KeyHandlerException
		 *             if something went wrong.
		 */
		public void addKeys(KeyObject[] key, KeyIdentifier[] idDetails,
				KeyHandlerParameters[] parameters) throws KeyHandlerException {
			try{
				if (!(key instanceof KeyData[])) {
	        		throw new KeyHandlerException("Unknown KeyObject type found");
	        	}
	            
				KeyPacket primaryKeyPacket = psk.getSecretKeyPacket();
	            KeyPacket currentKeyPacket = null;
	            OpenPGPAddSecretKeyParameters currentParam = null;
	            
	            // create / append byte array
	            ByteArrayOutputStream baos = new ByteArrayOutputStream();
	            OpenPGPPacketOutputStream out = new OpenPGPPacketOutputStream(baos);
	            
	            // iterate through all given keys, first element is primary
	            for (int n = 0; n < key.length; n++) {
	                
	                // check initial parameters
	                if ((key==null) || (key[n]==null)) {
	                    throw new KeyHandlerException("Key material is null.");
	                }
	                
	                // it is ok for subkeys to have no ID details

	                if ((parameters==null) || (parameters[n]==null)) {
	                    throw new KeyHandlerException("Key parameter is null.");
	                }
	                
	                if (!(parameters[n] instanceof OpenPGPAddKeyParameters)) {
	                    throw new KeyHandlerException(
	                    		"Key parameter is the wrong type.");
	                }
	                
	                // create key packet
	                currentParam = (OpenPGPAddSecretKeyParameters)parameters[n];
	                
	                // this is a subkey
                    if (key[n] instanceof OpenPGPKeyData) { 
                    	// try and import the key packet.
                        OpenPGPKeyData tmpKey = (OpenPGPKeyData)key[n];
                        
                        if (tmpKey.getKeyPacket() instanceof SecretSubkeyPacket) {
                        	//key[n] contains a SecretSubkeyPacket
                            currentKeyPacket = tmpKey.getKeyPacket(); 
                        } else {
                            throw new KeyHandlerException("Key "+n+" does " +
                            		"not appear to be a Secret Subkey Packet.");
                        }
                        
                    } else {
                        currentKeyPacket = new SecretSubkeyPacket(
                        		currentParam.getCreationDate(), 
                        		currentParam.getPublicKeyAlgorithm(), 
                        		currentParam.getSymmetricAlgorithm(), 
                        		createS2K(currentParam.getHashAlgorithm()), 
                        		currentParam.getPassPhrase(), 
                        		key[n].getKeyData().getKey());
                    }
	                
	                // write key packet
	                out.writePacket(currentKeyPacket);
	                out.writePacket(trust);
	                
	                SecretKeyPacket secretKeyPacket = psk.getSecretKeyPacket();
					secretKeyPacket.decryptKeyData(passPhrase.getPassphraseData());
	                
	                // generate and write subkey signature
                    byte [] tmp = generateSubKeyHashData(
                    		primaryKeyPacket.encodePacketBody(),
                    		currentKeyPacket.encodePacketBody());
                   
                    out.writePacket(new SignaturePacket(generateSubkeySignature(
                    		secretKeyPacket.getKeyData().getPrivateKey(),
                    		primaryKeyPacket.getKeyID(), currentParam, tmp)));
                    out.writePacket(trust);
	            }
	            
	            // close stream
	            out.close();
	            OpenPGPPublicSubkeyTrap.this.secretKeyData = baos.toByteArray();
	            baos.close();
	            OpenPGPPublicSubkeyTrap.this.updatePrimarySigningKey();
	            
	        } catch (Exception e) {
	            throw new KeyHandlerException(e.getMessage());
	        }
		}
		
		/** Method to return a readable description of this object
	     * @return A readable description of this object
	     */
	    public String getDescription() {
	    	return "OpenPGP Secret Subkey Trap";
	    }

		/** This method is unsupported in this implementation
		 * @see core.keyhandlers.KeyHandler#changeSetting(
		 * core.keyhandlers.KeyHandlerParameters)
		 */
		public void changeSetting(KeyHandlerParameters parameters)
				throws KeyHandlerException {
			throw new UnsupportedOperationException();
		}
	}

}
