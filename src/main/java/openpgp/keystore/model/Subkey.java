package openpgp.keystore.model;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Iterator;
import javax.swing.tree.MutableTreeNode;
import javax.swing.tree.TreeNode;

import openpgp.keystore.KeyStoreTrustManager;
import openpgp.keystore.TrustValues;
import openpgp.keystore.exceptions.*;
import openpgp.keystore.util.*;
import core.algorithmhandlers.PassPhrase;
import core.algorithmhandlers.openpgp.packets.PublicSubkeyPacket;
import core.algorithmhandlers.openpgp.packets.SecretSubkeyPacket;
import core.algorithmhandlers.openpgp.packets.SignatureMaterial;
import core.algorithmhandlers.openpgp.packets.SignaturePacket;
import core.algorithmhandlers.openpgp.packets.TrustPacket;
import core.algorithmhandlers.openpgp.packets.V4SignatureMaterial;
import core.algorithmhandlers.openpgp.packets.v4signature.ReasonForRevocationSubPacket;
import core.exceptions.AlgorithmException;

/** Wrapper class representing a subkey
 * @version $Id: Subkey.java,v 1.5 2007-08-25 14:06:57 nigelb Exp $
 */
public class Subkey extends KeyPair {
	
	// Whether the subkey binding signature has been verified
    private boolean isVerified = false;
    
    /** The primary constructor
     * @param privateSubkeyPkt The private key packet for this subkey pair
     * @param publicSubkeyPkt The public key packet for this subkey pair
     */
    public Subkey(SecretSubkeyPacket privateSubkeyPkt, PublicSubkeyPacket publicSubkeyPkt) {
    	setPrivateKey(privateSubkeyPkt);
    	setPublicKey(publicSubkeyPkt);
    	signatures = new ArrayList();
    }
    
    /** Constructor
     * @param privateKeyPkt The private key packet for this subkey pair
     */
    public Subkey(SecretSubkeyPacket privateSubkeyPkt) {
    	this(privateSubkeyPkt, KeyUtils.getPublicSubkeyPacket(privateSubkeyPkt));
    }
    
    /** Constructor
     * @param publicSubkeyPkt The public key packet for this subkey pair
     */
    public Subkey(PublicSubkeyPacket publicSubkeyPkt) {
    	this(null, publicSubkeyPkt);
    }
    
    /** Adds a signature verifying the subkey 
     * @param signature The signature to be added to the subkey
     */
    public void addSignature(Signature signature) {
    	if (signature.getSignatureType() == SignaturePacket.SUBKEY_REVOCATION) {
    		setRevocationSignature(signature);
    	} else if (signature.getSignatureType() == SignaturePacket.SUBKEY_BIND) {
    		// there should only ever be one subkey binding signature per subkey
    		signatures.add(signature);
    	} else {
    		// no other signature type accepted for a subkey
    		System.err.println("Unrecognised signature type attached to subkey");
    	}
    }
    
    /** @return the date and time that this primary signing expires, or 
	 * null if it cannot be found - if it cannot be found it is assumed to
	 * not expire. The expiry date can be changed by the user.
	 */
	public Date getExpirationDate() {
		Date expiry = null;
		Signature sbs = getSubkeyBindingSignature();
		if (sbs != null) {
			Date cd = getCreationDate();
			long expiryTimeSeconds = sbs.getKeyExpirationTime();
			if (expiryTimeSeconds > 0 && cd != null) {
				expiry = new Date(cd.getTime() + (expiryTimeSeconds * 1000));
			}
		}
		return expiry;
	}
	
	/** @return The subkey binding signature, that binds this subkey to the
	 * primary signing key, or null if it cannot be found. There should only
	 * be one subkey binding signature per subkey.
	 */
	private Signature getSubkeyBindingSignature() {
		Signature subkeyBindingSignature = null;
		for (Iterator it = getSignatureIterator(); it.hasNext();) {
			Signature sig = (Signature)it.next();
			if (sig.getSignatureType() == SignaturePacket.SUBKEY_BIND) {
				subkeyBindingSignature = sig;
				break;
			}
		}
		return subkeyBindingSignature;
	}
	
	/** Sets the status of this subkey to revoked
	 * @param signature The revocation signature to apply to the subkey  
	 */
	public void setRevocationSignature(Signature signature) {
		// Initial validation:
		// Only revocation signatures by the primary key holding the subkey
		// being revoked, or by an authorised revocation key, should be 
		// considered valid revocation signatures
		String signingKeyID = ((PrimarySigningKey)getParent()).getLongKeyID();
		if (signature.getSigningKeyLongID().equals(signingKeyID)) {
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
					signature.getSigningKeyLongID() + ", signing key " +
					"ID = " + signingKeyID);
		}
	}
	
	/** @see openpgp.keystore.model.Revocable#revoke()  */
	public void revoke(PrimarySigningKey revoker, PassPhrase passPhrase, int reason)
			throws RevocationException, KeyMismatchException {
		// make sure the subkey isn't already revoked - can't revoke it twice
		if (this.isRevoked) {
			throw new RevocationException("Subkey is already revoked");
		}
		// make sure that the revoker is the top-level signature key that is
		// bound to this subkey
		PrimarySigningKey parent = (PrimarySigningKey)this.getParent();
		if (!revoker.getLongKeyID().equals(parent.getLongKeyID())) {
			throw new KeyMismatchException("Can't revoke subkey " + 
					getShortKeyID() + " with key " + revoker.getShortKeyID());
		}
		// revoke the key
		try {
			Signature revocation = null;
			// decrypt the key data
			revoker.secretKeyPacket.decryptKeyData(passPhrase.getPassphraseData());
			// now the data is decrypted the private key is accessible
			PrivateKey privateKey = revoker.secretKeyPacket.getKeyData().getPrivateKey();
			
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			Signature.writeKey(parent.publicKeyPacket, baos);
			Signature.writeKey(this.publicKeyPacket, baos);
			byte[] dataToSign = baos.toByteArray();
			
			V4SignatureMaterial signatureMaterial = new V4SignatureMaterial(
		        	privateKey, // signing key
		            0, // revocation does not expire
		            revoker.secretKeyPacket.getKeyID(), // the key ID
		            SignaturePacket.SUBKEY_REVOCATION, // signature type
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
			// important: re-sign after adding one or more hashed subpackets 
			signatureMaterial.sign(privateKey, dataToSign);
			
			// make a new revocation signature packet
			revocation = new Signature(new SignaturePacket(signatureMaterial));
			
			// set up the signature trust - must be a new trust packet
			byte[] trustBytes = new byte[1];
			trustBytes[0] = revoker.getTrust().getTrust()[0];
			revocation.setTrust(new TrustPacket(trustBytes));
			
			// apply the revoked trust value (not trusted) and set as revoked
			KeyStoreTrustManager.applyTrust(this, 
					TrustValues.OWNERTRUST_NOT_USUALLY_TRUSTED);
			addSignature(revocation);
		} catch(Exception e) {
			e.printStackTrace();
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
		// make sure that the verifying key is the top-level signature key that
		// is bound to this subkey
		PrimarySigningKey parent = (PrimarySigningKey)this.getParent();
		if (!key.getLongKeyID().equals(parent.getLongKeyID())) {
			throw new KeyMismatchException("Can't verify revocation of " +
					"subkey " + getShortKeyID() + " with key " + 
					key.getShortKeyID());
		}
		if (this.isRevoked() && getRevocationSignature() != null) {
			debug.Debug.println(1, "Verifying subkey revocation signature for " +
					"key ID " + this.getShortKeyID());
			try {
				// retrieve the revocation signature to verify
				Signature revocationSig = getRevocationSignature();
				// make sure the signing key matches the revocation signer
				if (!key.getLongKeyID().equals(
						revocationSig.getSigningKeyLongID())) { 
					throw new KeyMismatchException(
						"The key ID of the key identified as the signing key " +
						"does not match the signers key ID on the signature"); 
				}
				// get the same data as the key revocation was over
				ByteArrayOutputStream baos = new ByteArrayOutputStream();
				Signature.writeKey(parent.publicKeyPacket, baos);
				Signature.writeKey(this.publicKeyPacket, baos);
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
					debug.Debug.println(1, "Discarding invalid subkey " +
							"revocation signature on subkey ID " + 
							this.getShortKeyID());
					this.isRevoked = false;
					this.revocationSignature = null;
				}
			} catch(AlgorithmException e) {
				throw new RevocationException(e.getMessage());
			} catch(IOException e) {
				throw new RevocationException(e.getMessage());
			}
		} else {
			throw new RevocationException("This subkey is not revoked");
		}
		return isValidSignature;
	}
	
	/** Method to verify the subkey binding signature. This method requires the 
	 * public key corresponding to the private key that was used to create the
	 * subkey binding signature, for verification.
	 * @param key The primary signing key
	 * @return true if the revocation signature is valid, false if not valid
	 */
	public boolean verifyBindingSignature()
			throws VerificationException, KeyMismatchException {
		// The signature is computed over the same data as the object that
		// it revokes. If it fails the verification, unset the revoked flag, 
		// and discard the revocation signature.
		boolean isValidSignature = false;
		PrimarySigningKey parent = (PrimarySigningKey)getParent();
		debug.Debug.println(1, "Verifying subkey binding signature " +
				"made by signing key ID " + parent.getShortKeyID() + " over " +
				"itself and subkey ID " + this.getShortKeyID());
		Signature sbs = null;  // subkey binding signature
		// sanity check 1 - every subkey must have a signature
		Iterator it = this.getSignatureIterator(); 
		if (it.hasNext()) {
			sbs = (Signature)it.next();
		} else {
			throw new VerificationException("No subkey binding signature exists!");
		}
		// sanity check 2 - the signature must be made by the parent signing key
		if (!parent.getLongKeyID().equals(sbs.getSigningKeyLongID())) { 
			throw new KeyMismatchException("The key ID of the signing key " +
					"does not match the signers key ID on the signature"); 
		}
		// sanity check 3 - the signature type must be 'subkey binding'
		SignaturePacket sigPacket = sbs.getSignaturePacket();
		int type = sigPacket.getSignatureData().getSignatureType();
		if (type == SignaturePacket.SUBKEY_BIND) {
			try {
				// get the same data as the subkey binding was over
				ByteArrayOutputStream baos = new ByteArrayOutputStream();
				Signature.writeKey(parent.publicKeyPacket, baos);
				Signature.writeKey(this.publicKeyPacket, baos);
				byte[] dataToVerify = baos.toByteArray();
				// verify the revocation signature
				isValidSignature = sigPacket.getSignatureData().verify(
						parent.getPublicKeyPacket().getKeyData().getPublicKey(),
						dataToVerify);
				// if signature is valid, mark signature and subkey as verified
				if (isValidSignature) {
					sbs.setVerified(isValidSignature);
					setVerified(isValidSignature);
				} else {
					debug.Debug.println(1, "Invalid subkey binding signature");
				}
			} catch(Exception e) {
				throw new VerificationException(e.getMessage());
			}
		} else {
			throw new VerificationException(
					"This signature is not a subkey binding signature");
		}
		return isValidSignature;
	}

	// hashtable, used by absorb() method
	private Hashtable absorbTable = new Hashtable();
	
	/** This method allows a Subkey to be absorbed by this one. This is used
	 * in the merging of a public keyring and a private keyring, or for the 
	 * merging of a private and public subkey pair during subkey generation.
	 * @param joining The Subkey to be joined into this one.
	 */
	public void absorb(Subkey joining) throws KeyMismatchException {
		if (!this.longKeyID.equals(joining.longKeyID)) {
			throw new KeyMismatchException("Cannot absorb mismatched Subkeys");
		}
		if (!this.hasPrivateKeyPart() && joining.hasPrivateKeyPart()) {
			// add private subkey
			this.setPrivateKey(joining.secretKeyPacket);
		}
		if (!this.hasPublicKeyPart() && joining.hasPublicKeyPart()) {
			// add public subkey
			this.setPublicKey(joining.publicKeyPacket);
		}
		// merge signatures (though the signatures should be the same)
		absorbTable.clear();
		for (Iterator it = this.signatures.iterator(); it.hasNext();) {
			Signature sig = (Signature)it.next();
			absorbTable.put(sig.getSigningKeyLongID(), sig);  // populate hashtable
		}
		for (Iterator it = joining.signatures.iterator(); it.hasNext();) {
			Signature jsig = (Signature)it.next();  // joining signature
			if (!absorbTable.containsKey(jsig.getSigningKeyLongID())) {  
				this.signatures.add(jsig);  // add missing signature
			}
		}
	}

	/** @see javax.swing.tree.TreeNode#children() */
	public Enumeration children() {
		return null;
	}

	/** @see javax.swing.tree.TreeNode#getAllowsChildren() */
	public boolean getAllowsChildren() {
		return false;
	}

	/** @see javax.swing.tree.TreeNode#getChildAt(int) */
	public TreeNode getChildAt(int childIndex) {
		return null;
	}

	/** @see javax.swing.tree.TreeNode#getChildCount() */
	public int getChildCount() {
		return 0;
	}

	/** @see javax.swing.tree.TreeNode#getIndex(javax.swing.tree.TreeNode) */
	public int getIndex(TreeNode node) {
		return -1;
	}

	/** @see javax.swing.tree.TreeNode#getParent() */
	public TreeNode getParent() {
		return parentNode;
	}

	/** @see javax.swing.tree.TreeNode#isLeaf() */
	public boolean isLeaf() {
		return true;
	}
	
	/** Adds child to the receiver at index. */
	public void insert(MutableTreeNode child, int index) {
		throw new UnsupportedOperationException();
	}

	/** Removes the child at index from the receiver. */
	public void remove(int index) {
		throw new UnsupportedOperationException();
	}

	/** Removes node from the receiver. */
	public void remove(MutableTreeNode node) {
		throw new UnsupportedOperationException();
	}

	/** @see java.lang.Object#toString() */
	public String toString() {
		return "Subkey [ID: " + this.getShortKeyID() + "]";
	}
	
	/** @return Whether the subkey binding signature is verified as valid */
	public boolean isVerified() {
		return this.isVerified;
	}

	/** @param isVerified Whether the subkey binding signature is verified 
	 * as valid 
	 */
	protected void setVerified(boolean isVerified) {
		this.isVerified = isVerified;
	}

}