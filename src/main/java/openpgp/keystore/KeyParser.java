package openpgp.keystore;

import java.io.*;
import java.util.*;

import openpgp.keystore.exceptions.*;
import openpgp.keystore.model.*;
import core.algorithmhandlers.openpgp.OpenPGPPacketInputStream;
import core.algorithmhandlers.openpgp.packets.*;
import core.exceptions.AlgorithmException;

/** <p>Class to manage the parsing of the Keyring file.</p>
 * <p>The read part of this class is written in the style of a simple language
 * parser. This approach allows the verification of the structure of the file. 
 * The following EBNF represents the structure of a Public/Private keyring:</p>
 * <pre>
 * PublicKeyring = {PublicCertificate}.
 * PrivateKeyring = {PrivateCertificate}.
 * PublicCertificate = 
 *         PublicPrimaryKey UserID {UserID} {UserAttribute} {PublicSubkey}.
 * PrivateCertificate = 
 *         PrivatePrimaryKey UserID {UserID} {UserAttribute} {PrivateSubkey}.
 * Signature = SignaturePacket [TrustPacket].
 * UserID = UserIDPacket [TrustPacket] {Signature}.
 * UserAttribute = UserAttributePacket [TrustPacket] {Signature}.
 * PublicPrimaryKey = PublicKeyPacket [TrustPacket] {Signature}.
 * PrivatePrimaryKey = SecretKeyPacket [TrustPacket] {Signature}.
 * PublicSubkey = PublicSubkeyPacket [TrustPacket] Signature [Signature].
 * PrivateSubkey = SecretSubkeyPacket [TrustPacket] Signature [Signature].
 * </pre>
 * <p>The primitive units of the packet language are PublicKeyPacket, 
 * SecretKeyPacket, PublicSubkeyPacket, SecretSubkeyPacket, UserIDPacket, 
 * UserAttributePacket, TrustPacket, and SignaturePacket.</p>
 * @version $Id: KeyParser.java,v 1.8 2007-08-27 20:38:28 nigelb Exp $
 */
public class KeyParser {
	
	// the expected type codes (underscore to avoid confusion about types)
	private final static int 
		SignaturePacket_ = 2,
		SecretKeyPacket_ = 5,
		PublicKeyPacket_ = 6,
		SecretSubkeyPacket_ = 7,
		TrustPacket_ = 12,
		UserIDPacket_ = 13,
		PublicSubkeyPacket_ = 14,
		UserAttributePacket_ = 17;

	// string representations of packet types, for error reporting purposes
	private final static String[] packetTypes = {
		"Reserved [0]",
		"PublicKeyEncryptedSessionKeyPacket",
		"SignaturePacket",
		"SymmetricKeyEncryptedSessionKeyPacket",
		"OnePassSignaturePacket",
		"SecretKeyPacket",
		"PublicKeyPacket",
		"SecretSubkeyPacket",
		"CompressedDataPacket",
		"SymmetricallyEncryptedDataPacket",
		"MarkerPacket",
		"LiteralDataPacket",
		"TrustPacket",
		"UserIDPacket",
		"PublicSubkeyPacket",
		"Reserved [15]", 
		"Reserved [16]",
		"UserAttributePacket",
		"SymmetricallyEncryptedIntegrityProtectedDataPacket",
		"ModificationDetectionCodePacket"
	};
	
	private OpenPGPPacketInputStream inputStream;  // the keyring file being read
    private Map primaryKeys = new Hashtable();  // key store, index is key ID
    private PrimarySigningKey currentKey;  // the currently building certificate
    private Packet cp;  // current packet (recently recognized)
	private Packet la;  // lookahead packet
	private int sym;  // symbol, contains la.getPacketHeader().getType()
	
	/** Method to call the 'scanner' (in this case the OpenPGPPacketInputStream
	 * object.
	 * @throws IOException
	 * @throws AlgorithmException
	 */
	private void scan() throws IOException, AlgorithmException {
		cp = la;
		//FIXME: need to read past badly processed packets, or fix to allow
		// processing of the misparsed packets, not set to 'EOF' when legacy
		// RSA keys (v3 keys) are read. It seems that keyservers output all 
		// v4 keys, then all v3 keys, so for now this workaround works (but
		// only returns v4 keys from key servers).
		try {
			la = inputStream.readPacket();
		} catch (AlgorithmException e) {
			la = null;
		}
		if (la != null) 
			sym = la.getPacketHeader().getType();
		else 
			sym = -1;
	}
	
	/** Method to read ahead if the current packet is what was expected.
	 * @param expected The packet type code that is expected
	 * @throws IOException In case of IO problems from the stream
	 * @throws AlgorithmException In case of stream structure problems
	 * @throws KeyringStructureException If the packet received is not what
	 * was expected 
	 */
	private void check(int expected) 
			throws IOException, AlgorithmException, KeyringStructureException {
		if (sym == expected) scan();
		else {
			throw new KeyringStructureException("Got " + packetTypes[sym] +
					" but " + packetTypes[expected] + " was expected");
		}
	}
	
	/** Method to convert structured data from a file into a Keyring object. 
	 * @param publicKeyring Name of an OpenPGP public keyring file path
	 * @param privateKeyring Name of an OpenPGP secret keyring file path
	 * @return a Keyring object, encapsulating the keys encoded in the files
	 * @throws KeyringStructureException In case of incorrectly structured byte
	 * streams.
	 */
	public KeyStore getKeyStore(String publicKeyring, String privateKeyring) 
			throws KeyringStructureException {
		
        debug.Debug.setLevel(1);
        primaryKeys.clear();
        KeyStore keyStore = new KeyStore();
        try {
			//Security.addProvider(new BouncyCastleProvider());
			
			if (publicKeyring != null) {
				// prepare public keyfile stream...
				inputStream = new OpenPGPPacketInputStream(
						new FileInputStream(publicKeyring));
				
				// start reading in keyring packets...
				publicKeyring();
				inputStream.close();
			}
			
			if (privateKeyring != null) {
				// prepare private keyfile stream...
				inputStream = new OpenPGPPacketInputStream(
						new FileInputStream(privateKeyring));
				
				// start reading in keyring packets...
				privateKeyring();
				inputStream.close();
			}
			mergeAndIdentify(keyStore);
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		return keyStore;
	}
	
	/** Method to convert structured data into a KeyStore object. 
	 * @param publicKeyData bytes structured in OpenPGP public key format
	 * @param privateKeyData bytes structured in OpenPGP private key format
	 * @return a Keyring object, encapsulating the keys encoded in the byte
	 * arrays
	 * @throws KeyringStructureException In case of incorrectly structured byte
	 * arrays.
	 */
	public KeyStore getKeyStore(byte[] publicKeyData, byte[] privateKeyData) 
			throws KeyringStructureException {

		primaryKeys.clear();
		KeyStore keyStore = new KeyStore();
		try {
			//Security.addProvider(new BouncyCastleProvider());
		
			if (publicKeyData != null) {
				// prepare public keyfile stream...
				inputStream = new OpenPGPPacketInputStream(
						new ByteArrayInputStream(publicKeyData));
				
				// start reading in keyring packets...
				publicKeyring();
				inputStream.close();
			}
			
			if (privateKeyData != null) {
				// prepare private keyfile stream...
				inputStream = new OpenPGPPacketInputStream(
						new ByteArrayInputStream(privateKeyData));
				
				// start reading in keyring packets...
				privateKeyring();
				inputStream.close();
			}
			mergeAndIdentify(keyStore);
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		return keyStore;
	}
	
	/** Method to convert structured data into a Keyring object. 
	 * @param publicKeyStream A stream of bytes structured in OpenPGP public 
	 * key format
	 * @param privateKeyStream A stream of bytes structured in OpenPGP private 
	 * key format
	 * @return a KeyStore object, encapsulating the key packets encoded in the 
	 * byte arrays
	 * @throws KeyringStructureException In case of incorrectly structured byte
	 * arrays.
	 */
	public KeyStore getKeyStore(InputStream publicKeyStream,
			InputStream privateKeyStream) throws KeyringStructureException {

		debug.Debug.setLevel(1);
		debug.Debug.println(1, "publicKeyData reference: " + publicKeyStream);
		debug.Debug.println(1, "privateKeyData reference: " + privateKeyStream);
		primaryKeys.clear();
		KeyStore keyStore = new KeyStore();
		try {
			//Security.addProvider(new BouncyCastleProvider());
		
			if (publicKeyStream != null) {
				// prepare public keyfile stream...
				inputStream = new OpenPGPPacketInputStream(publicKeyStream);
				
				// start reading in keyring packets...
				publicKeyring();
				inputStream.close();
			}
			
			if (privateKeyStream != null) {
				// prepare private keyfile stream...
				inputStream = new OpenPGPPacketInputStream(privateKeyStream);
				
				// start reading in keyring packets...
				privateKeyring();
				inputStream.close();
			}
			mergeAndIdentify(keyStore);
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		return keyStore;
	}
	
	/** Method to import subkeys from a pair of streams into an existing primary
	 * signing key object.
	 * @param psk The primary signing key, to which to add the keys
	 * @param publicSubkeyStream The public subkey stream
	 * @param privateSubkeyStream The private subkey stream
	 * @throws KeyringStructureException in case of stream structure problems
	 */
	public PrimarySigningKey getSubkeys(PrimarySigningKey psk, 
			InputStream publicSubkeyStream,
			InputStream privateSubkeyStream) throws KeyringStructureException {
		try {
			currentKey = psk;
			HashMap publicSubkeys = new HashMap();
			HashMap secretSubkeys = new HashMap();
		
			if (publicSubkeyStream != null) {
				// prepare public keyfile stream...
				inputStream = new OpenPGPPacketInputStream(publicSubkeyStream);
				
				// start reading in subkey packets...
				scan();
				while (sym == PublicSubkeyPacket_) {
					Subkey sk = publicSubkey();
					publicSubkeys.put(sk.getLongKeyID(), sk);
				}
				inputStream.close();
			}
			
			if (privateSubkeyStream != null) {
				// prepare private keyfile stream...
				inputStream = new OpenPGPPacketInputStream(privateSubkeyStream);
				
				// start reading in subkey packets...
				scan();
				while (sym == SecretSubkeyPacket_) {
					Subkey sk = privateSubkey();
					secretSubkeys.put(sk.getLongKeyID(), sk);
				}
				inputStream.close();
			}
			
			// this absorption step is necessary because, in the case of a 
			// public/private subkey pair, the secret subkey will overwrite
			// the public subkey with the same key ID during parsing using
			// the same PrimarySigningKey.
			for (Iterator it = secretSubkeys.keySet().iterator(); it.hasNext();) {
				String keyID = (String)it.next();
				if (publicSubkeys.containsKey(keyID)) {
					Subkey secretSubkey = (Subkey)secretSubkeys.get(keyID);
					Subkey publicSubkey = (Subkey)publicSubkeys.get(keyID);
					secretSubkey.absorb(publicSubkey);
					publicSubkey.absorb(secretSubkey);
				}
			}
			
		} catch (KeyringStructureException e) {
			throw e;
		} catch (KeyMismatchException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (AlgorithmException e) {
			e.printStackTrace();
		}
		return psk;
	}
	
	/** Method to fill in extra details in 
	 * the public and private certificates by cross-referencing key IDs 
	 * @param keyStore The key store to which the keys should be added
	 * @throws KeyMismatchException In case of mismatched keys
	 */
	private void mergeAndIdentify(KeyStore keyStore) throws KeyMismatchException {
		// merge the (currently separate) public and private certificates
		mergeCertificates();
		
		// identify the signatures with cross-referencing key IDs
		identifySignatures();
		
		// add the merged certificates to the keyring
		for (Iterator it1 = primaryKeys.values().iterator(); it1.hasNext();) {
			List certList = (List)it1.next();
			for (Iterator it2 = certList.iterator(); it2.hasNext();) {
				PrimarySigningKey pk = (PrimarySigningKey)it2.next();
				// only add key if it has public key or public/private key
				// (if only private key exists there is a keyring mismatch)
				if (pk.hasPublicKeyPart()) {
					keyStore.addKey(pk);
				} else{
					System.err.println("WARNING: Ignoring Key ID: " + 
							pk.getShortKeyID() + ". Reason: No matching " +
							"public key exists on the public keyring for " +
							"secret key.");
				}
			}
		}
		debug.Debug.println(1, "Data has " + keyStore.getChildCount() + 
				" key(s)");
	}
	
	/** Method to merge the public/private keys of matching certificates */
    private void mergeCertificates() throws KeyMismatchException {
    	for (Iterator it = primaryKeys.keySet().iterator(); it.hasNext();) {
    		// each certificate in the list has the same key ID
    		List certList = (List)primaryKeys.get((String)it.next());
    		
    		for (int i = 0; i < certList.size(); ++i) {
    			PrimarySigningKey key1 = (PrimarySigningKey)certList.get(i);
    			
    			for (int j = i + 1; j < certList.size(); ++j) {
    				PrimarySigningKey key2 = (PrimarySigningKey)certList.get(j);
    				
    				// extract user IDs, if they're equal, merge certificates
    				String uid1 = key1.getPrimaryEmailAddress();
    				String uid2 = key2.getPrimaryEmailAddress();
    				
    				if (uid1.equals(uid2)) { // key IDs and user IDs match
    					key1.absorb(key2, false);
    					certList.remove(j);
    					// element shift: pre-empt the '++j' in the 'for' loop
    					--j;
    				}
    			}
    		}
    	}
    }
    
    /** Method to fill in extra details in the public and private certificates 
     * by cross-referencing key IDs 
     */
    private void identifySignatures() {
    	// process all the signatures, matching key IDs with user IDs
    	for (Iterator x = primaryKeys.keySet().iterator(); x.hasNext();) {
    		// For each key ID get 1 (or more) certificates ...
    		String currentKeyID = (String)x.next();
    		List certList = (List)primaryKeys.get(currentKeyID);
    		for (int i = 0; i < certList.size(); ++i) {
    			// ... get each matching certificate signing key ...
    			PrimarySigningKey psk = (PrimarySigningKey)certList.get(i);
    			for (Iterator y = psk.getUserIDIterator(); y.hasNext();) {
    				// ... and each user bound to that key ...
    				UserID ub = (UserID)y.next();
    				for (Iterator z = ub.getSignatureIterator(); z.hasNext();) {
    					// ... and each signature certifying the bond ...
    					Signature sig = (Signature)z.next();
    					if (sig.getSigningKeyLongID().equals(currentKeyID)) {
    						// it's a self signature - set user id to primary
    						sig.setSigningUserID(psk);
    					} else {
    						List l = (List)primaryKeys.get(
    									sig.getSigningKeyLongID());
    						if (l != null && l.size() == 1) {
    							// one key ID matched!
    							PrimarySigningKey key = (PrimarySigningKey)l.get(0);
    							sig.setSigningUserID(key);
    						} // else no match or more than one key matched
    					}
    				} // for: each signature
    			} // for: each user ID
    		} // for: each certificate
    	} // for: each key id
    }
    
    // PublicKeyring = { PublicCertificate }.
    private void publicKeyring() 
    		throws KeyringStructureException, AlgorithmException, IOException {
    	debug.Debug.println(1, "xxx publicKeyring()");
    	scan();
    	for (;;) {
			if (sym != -1) publicCertificate(); 
			else break;
		}
    }
    
    // PrivateKeyring = { PrivateCertificate }.
    private void privateKeyring() 
    		throws KeyringStructureException, AlgorithmException, IOException {
    	debug.Debug.println(1, "xxx privateKeyring()");
    	scan();
    	for (;;) {
			if (sym != -1) privateCertificate(); 
			else break;
		}
    }
    
    // PublicCertificate = PublicPrimaryKey UserID { UserID } 
    //  {UserAttribute} { PublicSubkey }.
    private void publicCertificate() 
    		throws KeyringStructureException, AlgorithmException, IOException {
    	debug.Debug.println(1, "xxx publicCertificate()");
    	publicPrimaryKey();
    	for (;;) {
    		userID();
    		if (sym != UserIDPacket_) break;
    	}
    	while (sym == UserAttributePacket_) userAttribute();
    	while (sym == PublicSubkeyPacket_) publicSubkey();
    }
    
    // PrivateCertificate = PrivatePrimaryKey UserID { UserID }
    //  {UserAttribute} { PrivateSubkey }.
    private void privateCertificate() 
    		throws KeyringStructureException, AlgorithmException, IOException {
    	debug.Debug.println(1, "xxx privateCertificate()");
    	privatePrimaryKey();
    	for (;;) {
    		userID();
    		if (sym != UserIDPacket_) break;
    	}
    	while (sym == UserAttributePacket_) userAttribute();
    	while (sym == SecretSubkeyPacket_) privateSubkey();
    }
    
    // PublicPrimaryKey = PublicKeyPacket [ TrustPacket ] {Signature}.
    private void publicPrimaryKey() 
    		throws KeyringStructureException, AlgorithmException, IOException {
    	debug.Debug.println(1, "xxx publicPrimaryKey()");
    	// public key packet is always at the start of a new certificate
    	check(PublicKeyPacket_);
    	currentKey = new PrimarySigningKey((PublicKeyPacket)cp);
    	List keyList;
    	if (primaryKeys.containsKey(currentKey.getLongKeyID())) {
    		keyList = (List)primaryKeys.get(currentKey.getLongKeyID());
    	} else {
    		keyList = new ArrayList();
    		primaryKeys.put(currentKey.getLongKeyID(), keyList);
    	}
    	keyList.add(currentKey);
    	if (sym == TrustPacket_) {
    		scan();
    		currentKey.setTrust((TrustPacket)cp);
    	} else {
    		currentKey.setTrust(new TrustPacket(new byte[1]));
    	}
    	while (sym == SignaturePacket_) signature(currentKey);
    }
    
    // PrivatePrimaryKey = SecretKeyPacket [ TrustPacket ] {Signature}.
    private void privatePrimaryKey() 
    		throws KeyringStructureException, AlgorithmException, IOException {
    	debug.Debug.println(1, "xxx privatePrimaryKey()");
    	check(SecretKeyPacket_);
    	currentKey = new PrimarySigningKey((SecretKeyPacket)cp);
    	List keyList;
    	// check whether there's already an entry for this key ID ...
    	if (primaryKeys.containsKey(currentKey.getLongKeyID())) { // combine them
    		keyList = (List)primaryKeys.get(currentKey.getLongKeyID());
    	} else {
    		keyList = new ArrayList();
    		primaryKeys.put(currentKey.getLongKeyID(), keyList);
    	}
    	keyList.add(currentKey);
    	if (sym == TrustPacket_) {
    		scan();
    		currentKey.setTrust((TrustPacket)cp);
    	} else {
    		currentKey.setTrust(new TrustPacket(new byte[1]));
    	}
    	while (sym == SignaturePacket_) signature(currentKey);
    }
    
    // UserID = UserIDPacket [ TrustPacket ] { Signature }.
    private void userID() 
    		throws KeyringStructureException, AlgorithmException, IOException {
    	debug.Debug.println(1, "xxx userID()");
    	check(UserIDPacket_);
    	UserID uid = new UserID((UserIDPacket)cp, currentKey);
    	debug.Debug.println(1, "xxx              : " + uid.getUserID());
    	currentKey.addUserID(uid);
    	if (sym == TrustPacket_) {
    		scan();
    		uid.setTrust((TrustPacket)cp);
    	} else {
    		uid.setTrust(new TrustPacket(new byte[1]));
    	}
    	while (sym == SignaturePacket_) signature(uid);
    }
    
    // UserAttribute = UserAttributePacket [ TrustPacket ] { Signature }.
    private void userAttribute() 
    		throws KeyringStructureException, AlgorithmException, IOException {
    	debug.Debug.println(1, "xxx userAttribute()");
    	check(UserAttributePacket_);
    	UserAttribute ua = new UserAttribute((UserAttributePacket)cp, currentKey);
    	currentKey.addUserAttribute(ua);
    	if (sym == TrustPacket_) {
    		scan();
    		ua.setTrust((TrustPacket)cp);
    	} else {
    		ua.setTrust(new TrustPacket(new byte[1]));
    	}
    	while (sym == SignaturePacket_) signature(ua);
    }
    
    // Signature = SignaturePacket [ TrustPacket ].
    private void signature(Signable signable) 
    		throws KeyringStructureException, AlgorithmException, IOException {
    	debug.Debug.println(1, "xxx signature()");
    	check(SignaturePacket_);
    	Signature sig = new Signature((SignaturePacket)cp);
    	signable.addSignature(sig);
    	if (sym == TrustPacket_) {
    		scan();
    		sig.setTrust((TrustPacket)cp);
    	} else {
    		sig.setTrust(new TrustPacket(new byte[1]));
    	}
    }
    
    // PublicSubkey = PublicSubkeyPacket [ TrustPacket ] Signature [ Signature ].
    private Subkey publicSubkey() 
    		throws KeyringStructureException, AlgorithmException, IOException {
    	debug.Debug.println(1, "xxx publicSubkey()");
    	check(PublicSubkeyPacket_);
    	Subkey subkey = new Subkey((PublicSubkeyPacket)cp);
    	currentKey.addSubkey(subkey);
    	if (sym == TrustPacket_) {
    		scan();
    		subkey.setTrust((TrustPacket)cp);
    	} else {
    		subkey.setTrust(new TrustPacket(new byte[1]));
    	}
    	signature(subkey);
    	if (sym == SignaturePacket_) signature(subkey);
    	return subkey;
    }
    
    // PrivateSubkey = SecretSubkeyPacket [ TrustPacket ] Signature [ Signature ].
    private Subkey privateSubkey() 
    		throws KeyringStructureException, AlgorithmException, IOException {
    	debug.Debug.println(1, "xxx privateSubkey()");
    	check(SecretSubkeyPacket_);
    	Subkey subkey = new Subkey((SecretSubkeyPacket)cp);
    	currentKey.addSubkey(subkey);
    	if (sym == TrustPacket_) {
    		scan();
    		subkey.setTrust((TrustPacket)cp);
    	} else {
    		subkey.setTrust(new TrustPacket(new byte[1]));
    	}
    	signature(subkey);
    	if (sym == SignaturePacket_) signature(subkey);
    	return subkey;
    }
	
}
