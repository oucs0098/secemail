package openpgp.keystore.model;

import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Vector;
import java.util.List;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.TreeSet;
import java.util.Comparator;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.PrivateKey;
import core.algorithmhandlers.openpgp.packets.PublicKeyPacket;
import core.algorithmhandlers.openpgp.packets.SecretKeyPacket;
import core.algorithmhandlers.openpgp.packets.SignatureMaterial;
import core.algorithmhandlers.openpgp.packets.SignaturePacket;
import core.algorithmhandlers.openpgp.packets.TrustPacket;
import core.algorithmhandlers.openpgp.packets.UserIDPacket;
import core.algorithmhandlers.openpgp.packets.V4SignatureMaterial;
import core.algorithmhandlers.openpgp.packets.v4signature.*;
import core.algorithmhandlers.PassPhrase;
import core.exceptions.*;
import core.keyhandlers.identifiers.*;
import javax.swing.tree.MutableTreeNode;
import javax.swing.tree.TreeNode;
import openpgp.keystore.*;
import openpgp.keystore.exceptions.*;
import openpgp.keystore.util.*;

/** Wrapper class, representing a primary signing key (or key-pair)
 * @version $Id: PrimarySigningKey.java,v 1.13 2007-08-25 14:08:31 nigelb Exp $
 */
public class PrimarySigningKey extends KeyPair implements UserBindable {

    // The user IDs bound to this key (user IDs should be ordered)
    private Vector userIDs; 
    // The user attributes bound to this key
    private Vector userAttributes; 
    // zero or more subkeys
    private Hashtable subKeys;
    // combined: the children of this node
    private TreeSet children;
    
    /** The primary constructor
     * @param privateKeyPkt The private key packet for this key pair
     * @param publicKeyPkt The public key packet for this key pair
     */
    public PrimarySigningKey(SecretKeyPacket privateKeyPkt, PublicKeyPacket publicKeyPkt) {
    	setPrivateKey(privateKeyPkt);
    	setPublicKey(publicKeyPkt);
        userIDs = new Vector();
        userAttributes = new Vector();
        subKeys = new Hashtable();
        children = new TreeSet(new PrimaryKeyChildComparator());
    }
    
    /** Constructor
     * @param privateKeyPkt The private key packet for this subkey pair
     */
    public PrimarySigningKey(SecretKeyPacket privateKeyPkt) {
    	this(privateKeyPkt, KeyUtils.getPublicKeyPacket(privateKeyPkt));
    }
    
    /** Constructor
     * @param publicKeyPkt The public key packet for this subkey pair
     */
    public PrimarySigningKey(PublicKeyPacket publicKeyPkt) {
    	this(null, publicKeyPkt);
    }
    
    /** Adds a user ID to this primary signing key
     * @param userID The user ID object to be added
     */
    public void addUserID(UserID userID) {
    	userID.setParent(this);
        userIDs.add(userID);
        children.add(userID);
    }
    
    /** Adds a user ID to this primary signing key
     * @param userAttribute The user attribute object to be added
     */
    public void addUserAttribute(UserAttribute userAttribute) {
    	userAttribute.setParent(this);
    	userAttributes.add(userAttribute);
    	children.add(userAttribute);
    }

	/** @return an iterator to iterate over all user IDs for this key */
    public Iterator getUserIDIterator() {
        return userIDs.iterator();
    }
    
    /** @return an iterator to iterate over all user attributes for this key */
    public Iterator getUserAttributeIterator() {
        return userAttributes.iterator();
    }
    
    /** @return the number of user IDs attached to this key */
    public int getUserIDCount() {
        return userIDs.size();
    }
    
    /** Adds a signature, possibly revoking the primary key, possibly a 
     * direct-key signature. After a V4 key we expect an optional key revocation
     * signature followed by zero or more direct-key signatures.
     * @param signature The signature being applied to this primary signing key
     */
    public void addSignature(Signature signature) {
    	if (signature.getSignatureType() == SignaturePacket.KEY_REVOCATION) {
    		setRevocationSignature(signature);
    	} else {
    		signatures.add(signature);
    	}
    }
	
	/** method to return all user ID objects that declare themselves as
	 * primary user IDs
	 * @return a list of all the primary user IDs
	 */
	private List getPrimaryUserIDs() {
		List uidList = new ArrayList();
		if (!userIDs.isEmpty()) {
			for (Iterator it = userIDs.iterator(); it.hasNext();) {
				UserID uid = (UserID)it.next();
				if (uid.isPrimaryUserID()) uidList.add(uid);
			}
		}
		return uidList;
	}
	
	/** @return the first user ID associated with this key, or null if 
	 * one is not found. 
	 */
	public UserID getPrimaryUserID() {
		// This could be made more efficient, but any optimisations need to
		// take into account that the user IDs may be changed by the user
		UserID primaryUserID = null;
		List uidList = getPrimaryUserIDs();
		if (!uidList.isEmpty()) {  // >= 1 primary user ID returned
			if (uidList.size() > 1) {
				// sort on the basis of the most recent self-signature
				UserID mostRecent = null;
				long t = 0;  // maximum self-signature creation time so far
				for (Iterator it = uidList.iterator(); it.hasNext();) {
					UserID uid = (UserID)it.next();
					long cur = uid.getSelfSignature().getCreationDate().getTime();
					if (cur > t) {
						mostRecent = uid;
						t = cur;
					}
				}
				primaryUserID = mostRecent;
			} else {
				// only one primary user ID found
				primaryUserID = (UserID)uidList.get(0);
			}
		} else if (!userIDs.isEmpty()) { // set first/only as primary
			primaryUserID = (UserID)userIDs.get(0);
		}
		return primaryUserID;
	}
	
	/** @return the first user ID associated with this key */
	public String getPrimaryEmailAddress() {
		String userID = "";
		if (!userIDs.isEmpty()) {
			UserID uid = getPrimaryUserID();
			if (uid != null) userID = uid.getUserID();
		}
		return userID;
	}
	
	/** Method to find out whether this keypair can certify other keys. This
	 * implementation restricts signing to V4 keys only - V3 keys are 
	 * deprecated.
	 * @return true if this keypair can certify other keys
	 */
	public boolean canCertifyKeys() {
		boolean canCertify = false;
		if (isKeyPair() && secretKeyPacket.getVersion() == 4 && !isRevoked()
				&& !hasExpired()) {
			UserID uid = getPrimaryUserID();
			if (uid != null) {
				Signature selfsig = uid.getSelfSignature();
				if (selfsig != null) {
					canCertify = selfsig.canCertifyKeys();
				}
			}
		}
		return canCertify;
	}
	
	/** @return the first user ID associated with this key, or null if 
	 * no user ID is found 
	 */
	public OpenPGPStandardKeyIdentifier getPrimaryStandardKeyIdentifier() {
		OpenPGPStandardKeyIdentifier keyIdentifier = null;
		if (!userIDs.isEmpty()) {
			UserID uid = (UserID)userIDs.get(0);
			keyIdentifier = uid.getStandardKeyIdentifier();
		}
		return keyIdentifier;
	}
	
	/** @return the date and time that this primary signing expires, or 
	 * null if it cannot be found - if it cannot be found it is assumed to
	 * not expire. The expiry date can be changed by the user.
	 */
	public Date getExpirationDate() {
		Date expiry = null;
		UserID uid = getPrimaryUserID();
		if (uid != null) {
			Signature sig = uid.getSelfSignature();
			if (sig != null) {
				Date cd = getCreationDate();
				long expiryTimeSeconds = sig.getKeyExpirationTime();
				if (expiryTimeSeconds > 0 && cd != null) {
					expiry = new Date(cd.getTime() + (expiryTimeSeconds * 1000));
				}
			}
		}
		return expiry;
	}
	
	/** Method to set the key expiration date. This is stored in the primary
	 * user ID's self-signature. If the primary user ID, or its 
	 * self-signature, cannot be found, the expiry date will not be set.
	 * NOTE: NOT CURRENTLY USED
	 * @param expiryDate the date and time that this primary signing expires,
	 * or null if it does not expire. The expiry date should be changeable by
	 * the key owner.
	 */
	public void setExpirationDate(Date expiryDate) {
		UserID uid = getPrimaryUserID();
		if (uid != null) {
			Signature sig = uid.getSelfSignature();
			if (sig != null) {
				if (expiryDate == null) {
					sig.setKeyExpirationTime(0);
				} else {
					long expiryTimeInMillis = expiryDate.getTime();
					sig.setKeyExpirationTime(expiryTimeInMillis / 1000);
				}
			}
		}
	}
	
	/** Method to create a new user ID object, a binding between a user 
	 * and its key, and then produce a certification signature over the public
	 * key and it associated user ID.
	 * @param id The key identifier identifying the user ID to certify
	 * @param passPhrase The passphrase to use to decrypt this secret key
	 * @throws UserBindingException in case the user ID could not be added
	 */
	public void createBinding(OpenPGPStandardKeyIdentifier id,
			PassPhrase passPhrase) throws UserBindingException {
		// create a new user ID and certify it ...
		try {
			UserIDPacket userIDPacket = new UserIDPacket(id.getDefaultID());
			UserID uid = new UserID(userIDPacket, this);
			addUserID(uid);
			try {
				certifyBinding(uid, passPhrase, true, false, 0, 0);
			} catch(CertificationException e) {
				remove(uid); 
				throw new UserBindingException(e.getMessage());
			}
		} catch(KeyHandlerException e) {
			e.printStackTrace();
			throw new UserBindingException(e.getMessage());
		} catch(AlgorithmException e) {
			e.printStackTrace();
			throw new UserBindingException(e.getMessage());
		}
	}
	
	/** Method to sign a binding between the user and its key, in other words,
	 * produce a certification signature over the public key and it associated
	 * user ID, and add the signature to the user ID object.
	 * @param uid The user ID to certify
	 * @param passPhrase The passphrase to use to decrypt this secret key
	 * @param isExportable Whether the signature should be local or exportable
	 * @param isTrustSignature Whether the signature should include a trust
	 * subpacket, allowing either a trusted introducer or meta-introducer
	 * @param depth Only used if 'isTrustSignature' is set to true, legal values
	 * are 0 (normal signature), 1 (trusted introducer), and 2 (meta-introducer)
	 * @param amount Only used if 'isTrustSignature' is set to true, legal 
	 * values are 60 (partial trust) and 120 (complete trust)
	 * @throws CertificationException in case a problem occurred
	 */
	public void certifyBinding(UserID uid, PassPhrase passPhrase,
			boolean isExportable, boolean isTrustSignature,
			int depth, int amount) throws CertificationException {
		Signature signature = null;
		try {
			PrimarySigningKey primaryKeyToBeSigned = (PrimarySigningKey)uid.getParent();
			secretKeyPacket.decryptKeyData(passPhrase.getPassphraseData());
			
			// prepare the material for signing
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			Signature.writeKey(primaryKeyToBeSigned.publicKeyPacket, baos);
			Signature.writeUserID(uid.getStandardKeyIdentifier(), baos);
			byte[] dataToSign = baos.toByteArray();
			
			// make the signature material object
	        V4SignatureMaterial sigMaterial = new V4SignatureMaterial(
	        	secretKeyPacket.getKeyData().getPrivateKey(), // signing private key
	            0, // signature does not expire - can revoke if needed
	            secretKeyPacket.getKeyID(), // the key ID
	            SignaturePacket.GENERIC_UID, // signature type (generic certification)
	            secretKeyPacket.getAlgorithm(), // key algorithm
	            2, // hash algorithm - default to SHA1
	            dataToSign // the data to sign
	        );
	        
	        if (!isExportable) { // by default signatures are exportable
	        	ExportableCertification ec = new ExportableCertification(false);
	        	sigMaterial.addHashedSubPacket(ec);
	        }
                
            if (isTrustSignature && depth > 0) { // 0 means normal certification
                TrustSignatureSubPacket ts = 
                	new TrustSignatureSubPacket(depth, amount);
                sigMaterial.addHashedSubPacket(ts);
            }
                
	        // set key flags
	        KeyFlagsSubPacket kf = new KeyFlagsSubPacket(1);
	        kf.setMaySignDataFlag(true);
	        kf.setMayCertifyKeyFlag(true);
	        sigMaterial.addHashedSubPacket(kf);
	        
	        sigMaterial.sign(
        			secretKeyPacket.getKeyData().getPrivateKey(), dataToSign);
	        signature = new Signature(new SignaturePacket(sigMaterial));
	        
	        // set up the signature trust - must be a new trust packet
	        byte[] trustBytes = new byte[1];
			trustBytes[0] = getTrust().getTrust()[0];
			signature.setTrust(new TrustPacket(trustBytes));
			
			// set up the signature and add it
	        signature.setSigningUserID(this);
			uid.addSignature(signature);
		} catch(AlgorithmException e) {
			throw new CertificationException(e.getMessage());
		} catch(IOException e) {
			throw new CertificationException(e.getMessage());
		} catch(KeyHandlerException e) {
			throw new CertificationException(e.getMessage());
		}
	}
	
	/** Sets the status of this primary key to revoked
	 * @param signature The revocation signature to apply to the key
	 */
	public void setRevocationSignature(Signature signature) {
		// Only revocation signatures by the key being revoked, or by an
		// authorised revocation key, should be considered valid revocation
		// signatures
		if (signature.getSigningKeyLongID().equals(getLongKeyID())) {
			this.revocationSignature = signature;
			this.isRevoked = true;
			if (getTrust() == null) {
				try {
					setTrust(new TrustPacket(new byte[1]));
				} catch(AlgorithmException ignore) {}
			}
			getTrust().getTrust()[0] |= TrustValues.OWNERTRUST_KEY_REVOKED;
		} else {
			// Ignore the revocation, it failed the initial revocation test
			debug.Debug.println(1, "xxx Revocation signature failed the " +
					"validity test. Revocation signature key ID = " + 
					signature.getSigningKeyLongID() + ", key " +
					"ID = " + getLongKeyID());
		}
	}
	
	/** Method to revoke this public key
	 * To clarify the relationship between the two keys in this method, 
	 * this.publicKey is being revoked by key.publicKey 
	 * @see openpgp.keystore.model.Revocable#revoke()
	 */
	public void revoke(PrimarySigningKey revoker, PassPhrase passPhrase, int reason)
			throws RevocationException, KeyMismatchException {
		if (this.isRevoked) {
			throw new RevocationException("Key is already revoked");
		}
		if (!this.getLongKeyID().equals(revoker.getLongKeyID())) {
			throw new KeyMismatchException("Can't revoke key " + getShortKeyID() +
					" with key " + revoker.getShortKeyID());
		}
		// revoke the key
		try {
			Signature revocation = null;
			// decrypt the key data
			revoker.secretKeyPacket.decryptKeyData(
					passPhrase.getPassphraseData());
			// now the data is decrypted the private key is accessible
			PrivateKey privateKey = 
					revoker.secretKeyPacket.getKeyData().getPrivateKey();
			
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			Signature.writeKey(publicKeyPacket, baos);
			byte[] dataToSign = baos.toByteArray();
			
			V4SignatureMaterial signatureMaterial = new V4SignatureMaterial(
		        	privateKey, // signing key
		            0, // revocation does not expire
		            revoker.secretKeyPacket.getKeyID(), // the key ID
		            SignaturePacket.KEY_REVOCATION, // signature type
		            revoker.secretKeyPacket.getAlgorithm(), // key algorithm
		            2, // hash algorithm - default to SHA1
		            dataToSign // the data to sign
		        );
			
			// if reason is outside acceptable bounds use 'No reason specified'
			if (reason < 0x00 || reason > 0x03)
				reason = ReasonForRevocationSubPacket.NO_REASON;
			// add the 'reason for revocation' subpacket
			signatureMaterial.addHashedSubPacket(
					new ReasonForRevocationSubPacket(reason));
			// important to re-sign after adding one or more hashed subpackets 
			signatureMaterial.sign(privateKey, dataToSign);
			
			// make a new signature packet
			revocation = new Signature(new SignaturePacket(signatureMaterial));
			
			// reset the signature trust packet - must be a new trust packet
			byte[] trustBytes = new byte[1];
			trustBytes[0] = revoker.getTrust().getTrust()[0];
			revocation.setTrust(new TrustPacket(trustBytes));
			
			// apply the revoked trust value (not trusted) and set as revoked
			KeyStoreTrustManager.applyTrust(this, 
					TrustValues.OWNERTRUST_NOT_USUALLY_TRUSTED);
			addSignature(revocation);
		} catch(Exception e) {
			throw new RevocationException(e.getMessage());
		}
	}

	/** Method to verify a revocation signature. This method requires the 
	 * public key corresponding to the private key that was used to create this
	 * signature, for verification. 
	 * @param key The primary signing key
	 * @return true if the revocation signature is valid, false if not valid
	 */
	public boolean verifyRevocationSignature(PrimarySigningKey key)
			throws RevocationException, KeyMismatchException {
		// The signature is computed over the same data as the object that
		// it revokes. If it fails the verification, unset the revoked flag, 
		// and discard the revocation signature.
		boolean isValidSignature = false;
		if (this.isRevoked() && getRevocationSignature() != null) {
			debug.Debug.println(1, "Verifying primary signing key revocation " +
					"signature for key ID " + this.getShortKeyID());
			try {
				// retrieve the revocation signature to verify
				Signature revocationSig = getRevocationSignature();
				// make sure the signing key is correct
				if (!key.getLongKeyID().equals(
						revocationSig.getSigningKeyLongID())) { 
					throw new KeyMismatchException(
						"The key ID of the key identified as the signing key " +
						"does not match the signers key ID on the signature"); 
				}
				// get the same data as the key revocation was over
				ByteArrayOutputStream baos = new ByteArrayOutputStream();
				Signature.writeKey(publicKeyPacket, baos);
				byte[] dataToVerify = baos.toByteArray();
				// get the signature material from the signature
				SignatureMaterial sm = 
						revocationSig.getSignaturePacket().getSignatureData();
				// verify the revocation signature
				isValidSignature = sm.verify(
						key.getPublicKeyPacket().getKeyData().getPublicKey(),
						dataToVerify);
				// if the signature is valid, mark it as verified, else discard
				if (isValidSignature) {
					revocationSig.setVerified(isValidSignature);
				} else {
					debug.Debug.println(1, "Discarding invalid key revocation" +
							" signature for key ID " + this.getShortKeyID());
					this.isRevoked = false;
					this.revocationSignature = null;
				}
			} catch(AlgorithmException e) {
				throw new RevocationException(e.getMessage());
			} catch(IOException e) {
				throw new RevocationException(e.getMessage());
			}
		} else {
			throw new RevocationException("This key is not revoked");
		}
		return isValidSignature;
	}

	// hashtable, used by absorb() method
	private Hashtable absorbTable = new Hashtable();
	
	/** This method allows a primary signing key to be absorbed by this one.
	 * This is necessary when the public and private keys need to be joined
	 * into a single PrimaryKey.
	 * @param cert The PrimaryKey to be joined into this one.
	 */
	public void absorb(PrimarySigningKey joining, boolean replacePublicKey)
			throws KeyMismatchException {
		if (!this.longKeyID.equals(joining.longKeyID)) {
			throw new KeyMismatchException("Cannot absorb mismatched keys");
		}
		if (!this.hasPrivateKeyPart() && joining.hasPrivateKeyPart()) {
			this.setPrivateKey(joining.secretKeyPacket);  // add joining private key
		}
		if ((!this.hasPublicKeyPart() || replacePublicKey)
				&& joining.hasPublicKeyPart()) {
			// add joining public key
			this.setPublicKey(joining.publicKeyPacket);
		}
		
		// merge user IDs (though they should be identical)
		absorbTable.clear();
		for (Iterator it = this.userIDs.iterator(); it.hasNext();) {
			UserID uid = (UserID)it.next();
			absorbTable.put(uid.getUserID(), uid);
		}
		for (Iterator it = joining.userIDs.iterator(); it.hasNext();) {
			UserID juid = (UserID)it.next();  // joining user ID
			if (!absorbTable.containsKey(juid.getUserID())) {  // add binding if not found
				juid.setPrimarySigningKey(this);
				this.addUserID(juid);
			}
		}
		// merge signatures (though the signatures should be the same)
		absorbTable.clear();
		for (Iterator it = this.signatures.iterator(); it.hasNext();) {
			Signature sig = (Signature)it.next();
			absorbTable.put(sig.getSigningKeyLongID(), sig);  // populate hashtable
		}
		for (Iterator it = joining.signatures.iterator(); it.hasNext();) {
			Signature jsig = (Signature)it.next();  // joining signature
			if (!absorbTable.containsKey(jsig.getSigningKeyLongID())) {  // add sig
				this.signatures.add(jsig);
			}
		}
		// absorb the subkeys
		for (Iterator it = subKeys.keySet().iterator(); it.hasNext();) {
			String keyID = (String)it.next();
	    	if (joining.containsSubkeyID(keyID)) {
	    		Subkey thisSubkey = (Subkey)subKeys.get(keyID);
	    		Subkey thatSubkey = joining.getSubkeyByKeyID(keyID);
	    		thisSubkey.absorb(thatSubkey);
	    	}
		}
	}
	
	/** @see java.lang.Object#toString() */
	public String toString() {
		return getPrimaryEmailAddress();
	}
	
	/** Method to add a subkey. Use this method carefully, it will overwrite 
     * any other subkey with the same key ID.
     * @param subkey The subkey to add
     */
    public void addSubkey(Subkey subkey) {
    	subkey.setParent(this);
    	subKeys.put(subkey.getLongKeyID(), subkey);
        children.add(subkey);
    }
    
    /** @return An iterator to iterate over the subkeys */
    public Iterator getSubkeyIterator() {
        return subKeys.values().iterator();
    }
    
    /** @return Whether the certificate contains a particular subkey */ 
    public boolean containsSubkeyID(String keyID) {
    	return subKeys.containsKey(keyID);
    }
    
    /** @return A particular subkey, identified by its key ID */
    public Subkey getSubkeyByKeyID(String keyID) {
    	return (Subkey)subKeys.get(keyID);
    }
    
    /** @return A particular subkey, identified by its key ID */
    public int getSubkeyCount() {
    	return subKeys.size();
    }
    
    /** @see javax.swing.tree.TreeNode#children() */
	public Enumeration children() {
		return new IteratorWrapper(children.iterator());
	}

	/** @see javax.swing.tree.TreeNode#getAllowsChildren() */
	public boolean getAllowsChildren() {
		return true;
	}

	/** @see javax.swing.tree.TreeNode#getChildAt(int) */
	public TreeNode getChildAt(int childIndex) {
		return (TreeNode)new Vector(children).elementAt(childIndex);
	}

	/** @see javax.swing.tree.TreeNode#getChildCount() */
	public int getChildCount() {
		return children.size();
	}

	/** @see javax.swing.tree.TreeNode#getIndex(javax.swing.tree.TreeNode) */
	public int getIndex(TreeNode node) {
		return new Vector(children).indexOf(node);
	}

	/** @see javax.swing.tree.TreeNode#getParent() */
	public TreeNode getParent() {
		return parentNode;
	}

	/** @see javax.swing.tree.TreeNode#isLeaf() */
	public boolean isLeaf() {
		return children.isEmpty();
	}

    /** Adds child to the receiver at index. */
	public void insert(MutableTreeNode child, int index) {
		// this functionality should not be relied on - uses comparator instead
		children.add(child);
	}

	/** Removes the child at index from the receiver. */
	public void remove(int index) {
		Object child = new Vector(children).elementAt(index);
		remove((MutableTreeNode)child);
	}

	/** Removes node from the receiver. */
	public void remove(MutableTreeNode child) {
		children.remove(child);
		if (child instanceof UserID)
			userIDs.remove(child);
		else if (child instanceof UserAttribute)
			userAttributes.remove(child);
		else
			subKeys.remove(child);
	}
	
	/** Inner class to produce an ordering in the child elements - this is 
	 * necessary because the child elements are of different types.
	 */
	private class PrimaryKeyChildComparator implements Comparator {

		/** Method to compare the children of the primary signing key, to 
		 * produce a natural ordering. In this case, user IDs should occur
		 * first in the list, then user attributes, and subkeys after.
		 * @see java.util.Comparator#compare(java.lang.Object, java.lang.Object)
		 */
		public int compare(Object obj1, Object obj2) {
			int result = 0;
			if (obj1 instanceof UserID) {
				if (obj2 instanceof Subkey || obj2 instanceof UserAttribute) {
					result = -1;
				} else if (obj2 instanceof UserID) {
					UserID uid1 = (UserID)obj1;
					UserID uid2 = (UserID)obj2;
					result = uid1.getUserID().compareTo(uid2.getUserID());
				}
			} else if (obj1 instanceof UserAttribute) {
				if (obj2 instanceof Subkey) {
					result = -1;
				} else if (obj2 instanceof UserID) {
					result = 1;
				}
			} else if (obj1 instanceof Subkey) {
				if (obj2 instanceof UserID || obj2 instanceof UserAttribute) {
					result = 1;
				} else if (obj1 instanceof Subkey) {
					Subkey sk1 = (Subkey)obj1;
					Subkey sk2 = (Subkey)obj2;
					result = sk1.getLongKeyID().compareTo(sk2.getLongKeyID());
				}
			}
			return result;
		}
		
	}
    
}