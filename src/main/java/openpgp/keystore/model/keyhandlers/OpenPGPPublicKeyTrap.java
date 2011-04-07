package openpgp.keystore.model.keyhandlers;

import java.io.ByteArrayOutputStream;
import java.util.Iterator;
import openpgp.keystore.*;
import openpgp.keystore.model.*;
import openpgp.keystore.util.*;
import core.algorithmhandlers.keymaterial.RSAAlgorithmParameters;
import core.algorithmhandlers.openpgp.OpenPGPPacketOutputStream;
import core.algorithmhandlers.openpgp.packets.KeyPacket;
import core.algorithmhandlers.openpgp.packets.PublicKeyPacket;
import core.algorithmhandlers.openpgp.packets.PublicSubkeyPacket;
import core.algorithmhandlers.openpgp.packets.SecretKeyPacket;
import core.algorithmhandlers.openpgp.packets.SecretSubkeyPacket;
import core.algorithmhandlers.openpgp.packets.SignaturePacket;
import core.algorithmhandlers.openpgp.packets.UserIDPacket;
import core.algorithmhandlers.openpgp.packets.V4SignatureMaterial;
import core.exceptions.*;
import core.keyhandlers.KeyData;
import core.keyhandlers.KeyObject;
import core.keyhandlers.KeyHandlerParameters;
import core.keyhandlers.KeyIdentifier;
import core.keyhandlers.OpenPGPKeyring;
import core.keyhandlers.identifiers.OpenPGPStandardKeyIdentifier;
import core.keyhandlers.keydata.OpenPGPKeyData;
import core.keyhandlers.parameters.OpenPGPAddKeyParameters;
import core.keyhandlers.parameters.OpenPGPAddSecretKeyParameters;

/** <p>Class to trap public keys, for diversion to a keyring in memory.</p>
 * <p>Based on the OpenPGPPublicKeyring and OpenPGPSecretKeyring classes, but
 * intended for use in key generation, where the public key trap and the secret
 * key trap are used together to capture both public and private key data in a
 * separate thread. These classes do not send any data to a real file 
 * immediately, preferring to update a keyring in memory with the new keys, 
 * initialised with fresh trust packets, thereby giving the user the option to 
 * review, sign, and/or change details about the new key in the in-memory 
 * keyring before saving to the keyrings in persistent storage (on disk).</p>
 * <p>This mechanism should only be used where new public and secret
 * key data are being generated specifically for a given Keyring object.</p>
 * @version $Id: OpenPGPPublicKeyTrap.java,v 1.6 2007-08-27 21:13:26 nigelb Exp $
 */
public class OpenPGPPublicKeyTrap extends OpenPGPKeyring {

	/** Public key data data in byte array form, populated by public key trap */
	private byte[] publicKeyData = new byte[0];
	
	/** Secret key data data in byte array form, populated by secret key trap */
	private byte[] secretKeyData = new byte[0];
	
	/** The keyring parser, to use for parsing key data */
	private KeyParser keyParser;
	
	/** The key store to which the keys should be added */
	private KeyStore keyStore;
	
	/** The secret key handler to use in tandem with this when generating a 
	 * new keypair
	 */
	private OpenPGPSecretKeyTrap secretKeyTrap;
	
	/** Zero-argument constructor */
	public OpenPGPPublicKeyTrap(KeyParser keyParser, KeyStore keyStore) {
		super();
		this.keyParser = keyParser;
		this.keyStore = keyStore;
		this.secretKeyTrap = new OpenPGPSecretKeyTrap();
	}
	
	/** Accessor method to get access to the secret key data */ 
	public byte[] toByteArray() {
		return publicKeyData;
	}
	
	/** <p>Add a number of keys to the key store.</p>
	 * <p>Stores a key in the key store with details specified by idDetails and
	 * parameters as necessary.</p>
	 * <p>If a key with the same details already exists it is NOT replaced.</p>
	 * <p>The first key in the array is added as a primary key (which must be
	 * capable of signing), all other keys are added as sub keys.</p>
	 * 
	 * @param key[]
	 *            The keys to store. If key[n] is an instance of OpenPGPKeyData
	 *            then if possible the existing key packet is used. This enables
	 *            you to import keys from other key sources.
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

		try {
			if (!(key instanceof KeyData[])) {
        		throw new KeyHandlerException("Unknown KeyObject type found");
        	}
			
			KeyPacket primaryKeyPacket = null;
			KeyPacket currentKeyPacket = null;
			OpenPGPAddKeyParameters currentParam = null;

			// create / append byte array
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			OpenPGPPacketOutputStream out = new OpenPGPPacketOutputStream(baos);

			// iterate through all given keys, first element is primary
			for (int n = 0; n < key.length; n++) {

				// check initial parameters
				if ((key == null) || (key[n] == null))
					throw new KeyHandlerException("Key material is null.");

				if ((idDetails == null) || (idDetails[0] == null)) {
					// it is ok for non-primarykeys to have no ID details
					throw new KeyHandlerException(
							"Primary key has no user ID details!");
				}

				if ((parameters == null) || (parameters[n] == null))
					throw new KeyHandlerException("Key parameter is null.");

				if (!(parameters[n] instanceof OpenPGPAddKeyParameters))
					throw new KeyHandlerException(
							"Key parameter is the wrong type.");

				// create key packet
				currentParam = (OpenPGPAddKeyParameters) parameters[n];

				if (n == 0) { // this is the primary key
					if (key[n] instanceof OpenPGPKeyData) { 
						// if this is an OpenPGPKeyData key then try and import
						// the key packet.
						OpenPGPKeyData tmpKey = (OpenPGPKeyData) key[n];

						if ((tmpKey.getKeyPacket() instanceof PublicKeyPacket) &&
								(!(tmpKey.getKeyPacket() instanceof PublicSubkeyPacket)))
							// key[n] contains a PublicKeyPacket
							currentKeyPacket = tmpKey.getKeyPacket(); 
						else
							throw new KeyHandlerException("Key "+n+" does" +
									" not appear to be a Public Key Packet.");

					} else {
						currentKeyPacket = new PublicKeyPacket(currentParam
								.getCreationDate(), currentParam
								.getPublicKeyAlgorithm(), key[n].getKeyData().getKey());
					}
					primaryKeyPacket = currentKeyPacket;

				} else { // this is a subkey
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
				}

				// write key packet
				out.writePacket(currentKeyPacket);

				// if this is a primary key then write user ID
				if ((n == 0) && (idDetails[n] != null)) {
					if (!(idDetails[n] instanceof OpenPGPStandardKeyIdentifier)) {
						throw new KeyHandlerException(
								"User ID is of the wrong type!");
					}
					out.writePacket(
							new UserIDPacket(idDetails[n].getDefaultID()));
				}

				// generate and write signature
				V4SignatureMaterial sigMaterial = null;

				if (n == 0) { // primary key (sign user ID)
					byte[] tmp = generatePrimaryKeyHashData(
							(OpenPGPStandardKeyIdentifier) idDetails[n],
							primaryKeyPacket.encodePacketBody());
					
					sigMaterial = generatePrimarySignature(
							key[0].getKeyData().getKey().getPrivateKey(),
							primaryKeyPacket.getKeyID(),
							currentParam, tmp);

				} else { // sub key (signed with primary key)
					byte[] tmp = generateSubKeyHashData(
							primaryKeyPacket.encodePacketBody(), 
							currentKeyPacket.encodePacketBody());
					
					sigMaterial = generateSubkeySignature(
							key[0].getKeyData().getKey().getPrivateKey(), 
							primaryKeyPacket.getKeyID(),
							currentParam, tmp);

				}

				out.writePacket(new SignaturePacket(sigMaterial));
			}

			// close stream
			out.close();
			publicKeyData = baos.toByteArray();
			baos.close();
			updateKeyStore();

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
	private void updateKeyStore() {
		if (publicKeyData.length > 0 && secretKeyData.length > 0) {
			try {
				KeyStore newKeys = keyParser.getKeyStore(this.toByteArray(),
						secretKeyTrap.toByteArray());
				for (Iterator it = newKeys.getAllKeysIterator(); it.hasNext();) {
					PrimarySigningKey primaryKey = (PrimarySigningKey)it.next();
					// add trust packets
					KeyStoreTrustManager.applyClearTrust(primaryKey, true);
					KeyStoreTrustManager.applyTrust(primaryKey, 
							TrustValues.OWNERTRUST_ULTIMATE_TRUST);
					keyStore.addKey(primaryKey);
				}
			} catch(Exception e) {
				e.printStackTrace();
				System.err.println("Error: " + e.getMessage());
			}
		}
	}
	
	/** @return the secret key trap */
	public OpenPGPSecretKeyTrap getSecretKeyTrap() {
		return secretKeyTrap;
	}
	
	/** Method to return a readable description of this object
     * @return A readable description of this object
     */
    public String getDescription() {
    	return "OpenPGP Public Key Trap";
    }
	
	/**
	 * Inner class to trap secret keys, for diversion to a keyring in memory.
	 * Based on OpenPGPSecretKeyring, although this does not send any data to a
	 * real file, preferring to update a keyring with the data, via the outer 
	 * class, giving the user the option to change details about the key in the
	 * keyring before saving to the keyrings.
	 */
	private class OpenPGPSecretKeyTrap extends OpenPGPKeyring {
		
		/** Accessor method to get access to the secret key data */ 
		public byte[] toByteArray() {
			return OpenPGPPublicKeyTrap.this.secretKeyData;
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
	            
	            KeyPacket primaryKeyPacket = null;
	            KeyPacket currentKeyPacket = null;
	            OpenPGPAddSecretKeyParameters currentParam = null;
	            
	            // create / append byte array
	            ByteArrayOutputStream baos = new ByteArrayOutputStream();
	            OpenPGPPacketOutputStream out = new OpenPGPPacketOutputStream(baos);
	            
	            // itterate through all given keys, first element is primary
	            for (int n = 0; n < key.length; n++) {
	                
	                // check initial parameters
	                if ((key==null) || (key[n]==null)) {
	                    throw new KeyHandlerException("Key material is null.");
	                }

	                if ((idDetails==null) || (idDetails[0]==null)) {
	                	// it is ok for non primary keys to have no ID details
	                    throw new KeyHandlerException("Primary key has no " +
	                    		"user ID details!");
	                }

	                if ((parameters==null) || (parameters[n]==null)) {
	                    throw new KeyHandlerException("Key parameter is null.");
	                }
	                
	                if (!(parameters[n] instanceof OpenPGPAddKeyParameters)) {
	                    throw new KeyHandlerException(
	                    		"Key parameter is the wrong type.");
	                }
	                
	                // create key packet
	                currentParam = (OpenPGPAddSecretKeyParameters)parameters[n];
	                
	                if (n == 0) { // this is the primary key
	                    
	                    if (key[n] instanceof OpenPGPKeyData) { 
	                    	// if this is an OpenPGPKeyData key then try and 
	                    	// import the key packet.
	                        OpenPGPKeyData tmpKey = (OpenPGPKeyData)key[n];
	                        
	                        if ((tmpKey.getKeyPacket() instanceof SecretKeyPacket) &&
	                        		(!(tmpKey.getKeyPacket() 
	                        				instanceof SecretSubkeyPacket))) {
	                        	// key[n] contains a SecretKeyPacket
	                        	currentKeyPacket = tmpKey.getKeyPacket(); 
	                        } else {
	                        	throw new KeyHandlerException("Key "+n+" does" +
	                        			" not appear to be a Secret Key Packet.");
	                        }
	                        
	                    } else {
	                        currentKeyPacket = new SecretKeyPacket(
	                        		currentParam.getCreationDate(), 
	                        		currentParam.getPublicKeyAlgorithm(), 
	                        		currentParam.getSymmetricAlgorithm(),
									createS2K(currentParam.getHashAlgorithm()),
									currentParam.getPassPhrase(), key[n].getKeyData().getKey());
	                    }
	                    primaryKeyPacket = currentKeyPacket;
	                    
	                    if (currentParam.getPublicKeyAlgorithm() == 1)  { // RSA
	                    	RSAAlgorithmParameters rsaParams = 
	                    		(RSAAlgorithmParameters)key[n].getKeyData().getKey();
	                    }
	                    
	                } else { // this is a subkey
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
	                    
	                    if (currentParam.getPublicKeyAlgorithm() == 1)  { // RSA
	                    	RSAAlgorithmParameters rsaParams = 
	                    		(RSAAlgorithmParameters)key[n].getKeyData().getKey();
	                    }
	                }
	                
	                // write key packet
	                out.writePacket(currentKeyPacket);
	                
	                // if this is a primary key then write user ID
	                if ((n == 0) && (idDetails[n]!=null)) {
	                    if (!(idDetails[n] instanceof OpenPGPStandardKeyIdentifier)) {
	                    	throw new KeyHandlerException(
                    				"User ID is of the wrong type!");
	                    }
	                    out.writePacket(
	                    		new UserIDPacket(idDetails[n].getDefaultID()));
	                }
	                
	                // generate and write signature (only if this is a subkey)
	                if (n>0) { // sub key (signed with primary key)
	                	PublicKeyPacket pk = KeyUtils.getPublicKeyPacket(
	                			(SecretKeyPacket)primaryKeyPacket);
	                	PublicSubkeyPacket sk = KeyUtils.getPublicSubkeyPacket(
	                			(SecretSubkeyPacket)currentKeyPacket);
	                	
	                    byte [] tmp = generateSubKeyHashData(
	                    		pk.encodePacketBody(), 
	                    		sk.encodePacketBody());
	                   
	                    out.writePacket(
	                    		new SignaturePacket(generateSubkeySignature(
                				key[0].getKeyData().getKey().getPrivateKey(), 
                				primaryKeyPacket.getKeyID(),
                				currentParam, tmp)));
	                }
	            }
	            
	            // close stream
	            out.close();
	            OpenPGPPublicKeyTrap.this.secretKeyData = baos.toByteArray();
	            baos.close();
	            OpenPGPPublicKeyTrap.this.updateKeyStore();
	            
	        } catch (Exception e) {
	        	e.printStackTrace();
	            throw new KeyHandlerException(e.getMessage());
	        }
		}
		
		/** Method to return a readable description of this object
	     * @return A readable description of this object
	     */
	    public String getDescription() {
	    	return "OpenPGP Secret Key Trap";
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
