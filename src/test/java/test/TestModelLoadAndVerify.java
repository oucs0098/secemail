package test;

import junit.framework.TestCase;
import core.algorithmhandlers.openpgp.*;
import core.algorithmhandlers.openpgp.packets.*;
import core.keyhandlers.identifiers.*;
import core.exceptions.*;
import java.io.*;
import java.security.Security;
import java.util.*;
import openpgp.keystore.exceptions.*;
import openpgp.keystore.model.KeyStore;
import openpgp.keystore.model.PrimarySigningKey;
import openpgp.keystore.model.Signable;
import openpgp.keystore.model.Signature;
import openpgp.keystore.model.Subkey;
import openpgp.keystore.model.UserAttribute;
import openpgp.keystore.model.UserID;
import openpgp.keystore.util.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * <p>This test will attempt to gather the contents of a pgp keyring generated
 * by a third party app.</p>
 * <p>This test class is written in the style of a simple language parser. The 
 * following EBNF represents the structure of a Public/Private keyring:</p>
 * <pre>
 * PublicKeyring = {PublicCertificate}.
 * PrivateKeyring = {PrivateCertificate}.
 * PublicCertificate = PublicPrimaryKey UserID {UserID} {UserAttribute} {PublicSubkey}.
 * PrivateCertificate = PrivatePrimaryKey UserID {UserID} {UserAttribute} {PrivateSubkey}.
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
 * @version $Id: TestModelLoadAndVerify.java,v 1.11 2007-08-28 20:30:26 nigelb Exp $
 */
public class TestModelLoadAndVerify extends TestCase {
	
	// the type codes (underscored to avoid confusion about types)
	private final static int 
		PublicKeyEncryptedSessionKeyPacket_ = 1,
		SignaturePacket_ = 2,
		SymmetricKeyEncryptedSessionKeyPacket_ = 3,
		OnePassSignaturePacket_ = 4,
		SecretKeyPacket_ = 5,
		PublicKeyPacket_ = 6,
		SecretSubkeyPacket_ = 7,
		CompressedDataPacket_ = 8,
		SymmetricallyEncryptedDataPacket_ = 9,
		MarkerPacket_ = 10,
		LiteralDataPacket_ = 11,
		TrustPacket_ = 12,
		UserIDPacket_ = 13,
		PublicSubkeyPacket_ = 14,
		UserAttributePacket_ = 17,
		SymmetricallyEncryptedIntegrityProtectedDataPacket_ = 18,
		ModificationDetectionCodePacket_ = 19;

	// string representations of the packet types, for error reporting
	private final static String[] packetTypes = {
		"Reserved [0] - NOT TO BE USED",
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
	
	/** public keyring */
	public final String publickeyfile = "/testdata/RevocationTest.pkr";
	//public final String publickeyfile = "/testdata/proxy_pgp_revocation.pkr";
	/** Private keyring */
    public final String privatekeyfile = "/testdata/RevocationTest.skr";
	//public final String privatekeyfile = "/testdata/proxy_pgp_revocation.skr";
	
    
    private OpenPGPPacketInputStream keyfile;	// the keyring file
    
    private Map primaryKeys = new Hashtable(); // certificates, primary key ID is index
    private PrimarySigningKey currentKey; // the currently building certificate
    private Packet cp;	// current packet (recently recognized)
	private Packet la;	// lookahead packet
	private int sym;	// should always contain la.getPacketHeader().getType()
	
	private void scan() throws IOException, AlgorithmException {
		cp = la;
		la = keyfile.readPacket();
		if (la != null) 
			sym = la.getPacketHeader().getType();
		else 
			sym = -1;
	}
	
	private void check(int expected) throws IOException, AlgorithmException {
		if (sym == expected) scan();
		else error(packetTypes[expected] + " expected");
	}
	
	public static void error(String msg) { // print error and notify junit
		System.err.println("Packet Structure Error: " + msg);
		assertTrue( false );
	}
	
	/** <p>Execute the public keyring test.</p>
     * <p>You should implement this method with your test. Return true if the test
     * was successful, otherwise return false.</p>
     */
    public void testKeyringModelLoadAndVerify()
    {
        boolean allOK = true;
        //debug.Debug.setLevel(1);
        
        KeyStore keyStore = new KeyStore();
        try {
			System.out.println("Adding Bouncy Castle JCE provider...");
			Security.addProvider(new BouncyCastleProvider());

			// prepare public keyfile stream...
			keyfile = new OpenPGPPacketInputStream(
					getClass().getResourceAsStream(publickeyfile));
			
			// start reading in packets...
			scan();
			publicKeyring();
			
			// prepare private keyfile stream...
			keyfile = new OpenPGPPacketInputStream(
					getClass().getResourceAsStream(privatekeyfile));
			
			// start reading in packets...
			scan();
			privateKeyring();
			
			// merge the (currently separate) public and private certificates
			mergeCertificates();
			
			for (Iterator it1 = primaryKeys.values().iterator(); it1.hasNext();) {
				List certList = (List)it1.next();
				for (Iterator it2 = certList.iterator(); it2.hasNext();) {
					keyStore.addKey((PrimarySigningKey)it2.next());
				}
			}
			debug.Debug.println(1, "Got " + keyStore.getChildCount() + 
					" certificates in keyring");
			
		} catch (Exception e) {
			e.printStackTrace();
			allOK = false;
		}
		
		// Display the gathered certificates
		debug.Debug.println(1, "Loaded " + primaryKeys.size() + " key IDs:");
		for (Iterator it1 = primaryKeys.keySet().iterator(); it1.hasNext();) {
			String keyID = (String)it1.next();
			debug.Debug.println(1, "Key ID '" + keyID + "'");
			List keyList = (List)primaryKeys.get(keyID);
			for (Iterator it2 = keyList.iterator(); it2.hasNext();) {
				PrimarySigningKey pk = (PrimarySigningKey)it2.next();
				String type = "";
				if (pk.hasPublicKeyPart()) type += "PUBLIC ";
				if (pk.hasPrivateKeyPart()) type += "PRIVATE ";
				debug.Debug.println(1, "Key is " + type);
				debug.Debug.println(1, "First User ID '" + pk.getPrimaryEmailAddress() + "'");
			}
		}
		
		// Validate the certification & certification revocation signatures
		for (Iterator keyit = keyStore.getAllKeysIterator(); keyit.hasNext();) {
			PrimarySigningKey psk = (PrimarySigningKey)keyit.next();
			
			// validate key revocation signatures
			if (psk.isRevoked()) {
				try {
					boolean isValid = psk.verifyRevocationSignature(psk);
					debug.Debug.println(1, "Valid: " + isValid);
				} catch(KeyMismatchException e) {
					e.printStackTrace();
				} catch(RevocationException e) {
					e.printStackTrace();
				}
			}
			
			//TODO: validate any direct-key signatures (DK sigs not being used)
//			for (Iterator sigit = psk.getSignatureIterator(); sigit.hasNext();) {
//				Signature sig = (Signature)sigit.next();
//				** validate here **
//			}
			
			// validate certification signatures and their revocations
			for (Iterator ubi = psk.getUserIDIterator(); ubi.hasNext();) {
				UserID ub = (UserID)ubi.next();
				for (Iterator si = ub.getSignatureIterator(); si.hasNext();) {
					Signature sig = (Signature)si.next();
					try {
						OpenPGPKeyIDKeyIdentifier id = 
								new OpenPGPKeyIDKeyIdentifier(
										sig.getRawSigningKeyID());
						List keyList = keyStore.findPrimaryKeys(id);
						if (keyList != null && keyList.size() == 1) {
							PrimarySigningKey key = 
									(PrimarySigningKey)keyList.get(0);
							boolean result;
							if (sig.isRevoked()) {
								debug.Debug.println(1, "Verify revocation " +
										"from key ID " + key.getShortKeyID() +
										" (" + key.getPrimaryEmailAddress() + ")");
								result = sig.verifyRevocationSignature(key);
							} else {
								debug.Debug.println(1, "Verify certification " +
										"from key ID " + key.getShortKeyID() +
										" (" + key.getPrimaryEmailAddress() + ")");
								result = sig.verifyCertificationSignature(key);
							}
							debug.Debug.println(1, "Valid: " + result);
						} else {
							if (keyList == null)
								debug.Debug.println(1, "Error: Signing key " +
										"not found");
							else
								debug.Debug.println(1, "Error: " + 
										keyList.size() + " key matches found");
							allOK = false;
						}
					} catch(Exception e) {
						e.printStackTrace();
						allOK = false;
					}
				}
			}
			
			// validate subkey signature revocations
			for (Iterator ski = psk.getSubkeyIterator(); ski.hasNext();) {
				Subkey sk = (Subkey)ski.next();
				if (sk.isRevoked()) {
					try {
						boolean isValid = sk.verifyRevocationSignature(psk);
						debug.Debug.println(1, "Valid: " + isValid);
					} catch(KeyMismatchException e) {
						e.printStackTrace();
					} catch(RevocationException e) {
						e.printStackTrace();
					}
				}
				//TODO: validate subkey binding signature
			}
		}
		
        // tell JUnit the result
        assertTrue(allOK);
    }
    
    // merge the public and private keys of matching certificates
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
    
    // PublicKeyring = { PublicCertificate }.
    private void publicKeyring() throws AlgorithmException, IOException {
    	for (;;) {
			if (sym != -1) publicCertificate(); 
			else break;
		}
    }
    
    // PrivateKeyring = { PrivateCertificate }.
    private void privateKeyring() throws AlgorithmException, IOException {
    	for (;;) {
			if (sym != -1) privateCertificate(); 
			else break;
		}
    }
    
    // PublicCertificate = PublicPrimaryKey UserID { UserID } { PublicSubkey }.
    private void publicCertificate() throws AlgorithmException, IOException {
    	publicPrimaryKey();
    	for (;;) {
    		userID();
    		if (sym != UserIDPacket_) break;
    	}
    	while (sym == PublicSubkeyPacket_) publicSubkey();
    }
    
    // PrivateCertificate = PrivatePrimaryKey UserID { UserID } { PrivateSubkey }.
    private void privateCertificate() throws AlgorithmException, IOException {
    	privatePrimaryKey();
    	for (;;) {
    		userID();
    		if (sym != UserIDPacket_) break;
    	}
    	while (sym == SecretSubkeyPacket_) privateSubkey();
    }
    
    // PublicPrimaryKey = PublicKeyPacket [ TrustPacket ] {Signature}.
    private void publicPrimaryKey() throws AlgorithmException, IOException {
    	// public key packet is always at the start of a new certificate
    	check(PublicKeyPacket_);
    	currentKey = new PrimarySigningKey((PublicKeyPacket)cp);
    	List certificateList;
    	if (primaryKeys.containsKey(currentKey.getLongKeyID())) {
    		certificateList = (List)primaryKeys.get(currentKey.getLongKeyID());
    	} else {
    		certificateList = new ArrayList();
    		primaryKeys.put(currentKey.getLongKeyID(), certificateList);
    	}
    	certificateList.add(currentKey);
    	if (sym == TrustPacket_) {
    		scan();
    		currentKey.setTrust((TrustPacket)cp);
    	}
    	while (sym == UserAttributePacket_) userAttribute();
    	while (sym == SignaturePacket_) signature(currentKey);
    }
    
    // PrivatePrimaryKey = SecretKeyPacket [ TrustPacket ] {Signature}.
    private void privatePrimaryKey() throws AlgorithmException, IOException {
    	check(SecretKeyPacket_);
    	currentKey = new PrimarySigningKey((SecretKeyPacket)cp);
    	List certificateList;
    	// check whether there's already an entry for this key ID ...
    	if (primaryKeys.containsKey(currentKey.getLongKeyID())) { // combine pub/pri certificates
    		certificateList = (List)primaryKeys.get(currentKey.getLongKeyID());
    	} else {
    		certificateList = new ArrayList();
    		primaryKeys.put(currentKey.getLongKeyID(), certificateList);
    	}
    	certificateList.add(currentKey);
    	if (sym == TrustPacket_) {
    		scan();
    		currentKey.setTrust((TrustPacket)cp);
    	}
    	while (sym == UserAttributePacket_) userAttribute();
    	while (sym == SignaturePacket_) signature(currentKey);
    }
    
    // UserID = UserIDPacket [ TrustPacket ] { Signature }.
    private void userID() throws AlgorithmException, IOException {
    	check(UserIDPacket_);
    	UserID uid = new UserID((UserIDPacket)cp, currentKey);
    	currentKey.addUserID(uid);
    	if (sym == TrustPacket_) {
    		scan();
    		uid.setTrust((TrustPacket)cp);
    	}
    	while (sym == SignaturePacket_) signature(uid);
    }
    
    // UserAttribute = UserAttributePacket [ TrustPacket ] { Signature }.
    private void userAttribute() 
    		throws AlgorithmException, IOException {
    	check(UserAttributePacket_);
    	UserAttribute ua = new UserAttribute((UserAttributePacket)cp, currentKey);
    	currentKey.addUserAttribute(ua);
    	if (sym == TrustPacket_) {
    		scan();
    		ua.setTrust((TrustPacket)cp);
    	}
    	while (sym == SignaturePacket_) signature(ua);
    }
    
    // Signature = SignaturePacket [ TrustPacket ].
    private void signature(Signable signable) throws AlgorithmException, IOException {
    	check(SignaturePacket_);
    	Signature sig = new Signature((SignaturePacket)cp);
    	debug.Debug.println(1, "xxx Read Signature, Type: 0x" + 
    			StringHelper.toHexString(KeyUtils.toByteArray(
    					sig.getSignatureType())).substring(6));
    	signable.addSignature(sig);
    	if (sym == TrustPacket_) {
    		scan();
    		sig.setTrust((TrustPacket)cp);
    	}
    }
    
    // PublicSubkey = PublicSubkeyPacket [ TrustPacket ] Signature [ Signature ].
    private void publicSubkey() throws AlgorithmException, IOException {
    	check(PublicSubkeyPacket_);
    	Subkey subkey = new Subkey((PublicSubkeyPacket)cp);
    	currentKey.addSubkey(subkey);
    	if (sym == TrustPacket_) {
    		scan();
    		subkey.setTrust((TrustPacket)cp);
    	}
    	signature(subkey);
    	if (sym == SignaturePacket_) signature(subkey);
    }
    
    // PrivateSubkey = SecretSubkeyPacket [ TrustPacket ] Signature [ Signature ].
    private void privateSubkey() throws AlgorithmException, IOException {
    	check(SecretSubkeyPacket_);
    	Subkey subkey = new Subkey((SecretSubkeyPacket)cp);
    	currentKey.addSubkey(subkey);
    	if (sym == TrustPacket_) {
    		scan();
    		subkey.setTrust((TrustPacket)cp);
    	}
    	signature(subkey);
    	if (sym == SignaturePacket_) signature(subkey);
    }
}