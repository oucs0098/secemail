package openpgp.keystore.model;

import java.io.IOException;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.ArrayList;
import javax.swing.tree.MutableTreeNode;
import javax.swing.tree.TreeNode;
import openpgp.keystore.TrustValues;
import openpgp.keystore.util.*;
import core.algorithmhandlers.openpgp.OpenPGPPacketOutputStream;
import core.algorithmhandlers.openpgp.packets.KeyPacket;
import core.algorithmhandlers.openpgp.packets.PublicKeyPacket;
import core.algorithmhandlers.openpgp.packets.SecretKeyPacket;
import core.algorithmhandlers.openpgp.packets.TrustPacket;
import core.algorithmhandlers.openpgp.util.PublicKeyAlgorithmSettings;
import core.exceptions.AlgorithmException;
import core.keyhandlers.KeyData;
import core.keyhandlers.KeyObject;
import core.keyhandlers.keydata.OpenPGPKeyData;

/** Class to abstract all the common functionality of the public key classes,
 * PrimarySigningKey and Subkey.
 * @version $Id: KeyPair.java,v 1.2 2007-08-17 17:24:22 nigelb Exp $
 */
public abstract class KeyPair implements ExportableKeyringPacketWrapper,
		Signable, Revocable, Expirable, KeyStoreNode, KeyObject {
	
	/** The public key packet part */
	protected PublicKeyPacket publicKeyPacket;
	/** The private key packet part */
	protected SecretKeyPacket secretKeyPacket;
	/** The signature revoking this subkey (only non-null if revoked) */
    protected Signature revocationSignature;
    /** the key creation date/time */
    protected Date creationDate;
    /** whether this signature has been revoked (defaults to not revoked) */
    protected boolean isRevoked = false;
    /** The trust assigned to thie signing owner */
    protected TrustPacket keyTrust;
    /** The signatures making a statement about the key (and its bindings) */
    protected List signatures = new ArrayList();
    /** The 'short' key ID in string form with uninitialised value */
	protected String shortKeyID = "[Key ID Unavailable]";
	/** The 'long' key ID in string form with uninitialised value */
	protected String longKeyID = "[Key ID Unavailable]";
	/** The 'raw' key ID in byte array form */
	protected byte[] rawKeyID;
	/** The key 'fingerprint' in string form with uninitialised value */
	protected String fingerprint = "[Fingerprint Unavailable]";
	/** The parent node in the keyring tree */
    protected TreeNode parentNode;
    /** The key size, in bits, approximated onto a boundary */
    private int keySize;
    
    /** @return whether this subkey has the private key part */
    public boolean hasPrivateKeyPart() {
    	return (secretKeyPacket != null);
    }
    
    /** @return whether this subkey has the public key part */
    public boolean hasPublicKeyPart() {
    	return (publicKeyPacket != null);
    }
    
    /** @return whether this key has both private and public key parts */
    public boolean isKeyPair() {
    	return (secretKeyPacket != null && publicKeyPacket != null);
    }
    
    /** Accessor method to return key data */
	public KeyData getKeyData() {
		KeyData keyData;
		// one of privateKey and publicKey must be available
		if (secretKeyPacket != null) {  // default to returning the private key data
			keyData = new OpenPGPKeyData(secretKeyPacket);
		} else {
			keyData = new OpenPGPKeyData(publicKeyPacket);
		}
		return keyData;
	}
    
    /** Sets the signing trust for the owner of this key */
    public void setTrust(TrustPacket trustPkt) {
    	keyTrust = trustPkt;
    }
    
    /** Retrieves the signing trust for the owner of this key */
    public TrustPacket getTrust() {
        return keyTrust;
    }
    
    /** @return Whether this subkey has been revoked */
	public boolean isRevoked() {
		return isRevoked;
	}
	
	/** @return an iterator to iterate over the signature objects */
    public Iterator getSignatureIterator() {
        return signatures.iterator();
    }
    
    /** @return the key ID of the keypair */
	public String getShortKeyID() {
		return shortKeyID;
	}
	
	/** @return the key ID of the keypair */
	public String getLongKeyID() {
		return longKeyID;
	}
	
	/** @return a formatted public key cipher description */
	public String getPublicKeyAlgorithmText() {
		int algorithmCode;
		if (publicKeyPacket != null)
			algorithmCode = publicKeyPacket.getAlgorithm();
		else
			algorithmCode = secretKeyPacket.getAlgorithm();
		return PublicKeyAlgorithmSettings.getCipherDisplayText(algorithmCode);
	}
    
    /** @return the date and time that this subkey was created, or 
	 * null if it cannot be found.
	 */
	public Date getCreationDate() {
		if (creationDate == null) {
			KeyPacket keyPacket;
			if (this.hasPublicKeyPart()) {
				keyPacket = publicKeyPacket;
			} else {
				keyPacket = secretKeyPacket;
			}
			creationDate = new Date(keyPacket.getCreateDate() * 1000);
		}
		return creationDate;
	}
	
	/** Method to find out whether this key has expired 
	 * @return whether this key has passed its expiry date
	 */
	public boolean hasExpired() {
		boolean expired = false;
		Date expiryDate = getExpirationDate();
		if (expiryDate != null) {
			Date now = new Date();
			if (now.after(expiryDate)) expired = true;
		}
		return expired;
	}
	
	/** Mutator method.
	 * Sets up the private key attribute and the key identifier attributes
	 * @param privateKey the private key to set
	 */
	protected void setPrivateKey(SecretKeyPacket privateKey) {
		this.secretKeyPacket = privateKey;
		if (privateKey != null && publicKeyPacket == null) {
			try {
				setFingerprint(privateKey.getFingerprint());
				rawKeyID = privateKey.getKeyID();
				longKeyID = StringHelper.toHexString(privateKey.getKeyID());
				shortKeyID = "0x" + longKeyID.substring(8);
			} catch (AlgorithmException e) {
				e.printStackTrace();
			}
		}
	}
	
	/** Mutator method.
	 * Sets up the private key attribute and the key identifier attributes
	 * @param publicKey the public key to set
	 */
	protected void setPublicKey(PublicKeyPacket publicKey) {
		this.publicKeyPacket = publicKey;
		if (publicKey != null && secretKeyPacket == null) {
			try {
				setFingerprint(publicKey.getFingerprint());
				rawKeyID = publicKey.getKeyID();
				longKeyID = StringHelper.toHexString(publicKey.getKeyID());
				shortKeyID = "0x" + longKeyID.substring(8);
			} catch (AlgorithmException e) {
				e.printStackTrace();
			}
		}
	}
	
	/** Method to return the approximate, rounded-up size of the key, in bits
	 * @return An approximation of the key size - for example, although the 
	 * actual key in the key material might be 1022 bits or 1023 bits, the key
	 * size returned here would be 1024 bits.
	 */
	public int getKeySize() {
		if (this.keySize == 0) {
			this.keySize = KeyUtils.getKeySize(publicKeyPacket);
		}
		return this.keySize;
	}
	
	/** Method to set the fingerprint as a local formatted hex string, with
	 * spaces. This method of formatting a byte string in hex, in byte pairs,
	 * is used by both GnuPG and PGP, so it is treated as convention and
	 * followed.
	 * @param fp The fingerprint, as a string of bytes
	 */
	private void setFingerprint(byte[] fp) {
		StringBuffer buffer = new StringBuffer();
		byte[] bytePair = new byte[2];
		for (int i = 0; i < fp.length; i += 2) {
			bytePair[0] = fp[i];
			bytePair[1] = fp[i+1];
			buffer.append(StringHelper.toHexString(bytePair));
			buffer.append(" ");
		}
		fingerprint = buffer.toString().trim();
	}
	
	/** @see openpgp.keystore.model.KeyStoreNode#getIconType() */
	public int getIconType() {
		int iconType = 0;
		switch(publicKeyPacket.getAlgorithm()) {
			case PublicKeyAlgorithmSettings.RSA_ENCRYPTSIGN:
			case PublicKeyAlgorithmSettings.RSA_SIGN:
				if (isKeyPair()) {
					if (isRevoked() || hasExpired())
						iconType = RSA_DISABLED_KEY_PAIR_NODE;
					else
						iconType = RSA_KEY_PAIR_NODE;
				} else {
					if (isRevoked() || hasExpired())
						iconType = RSA_DISABLED_PUBLIC_KEY_NODE;
					else
						iconType = RSA_PUBLIC_KEY_NODE;
				}
				break;
			case PublicKeyAlgorithmSettings.DSA:
				if (isKeyPair()) {
					if (isRevoked() || hasExpired())
						iconType = DSA_DISABLED_KEY_PAIR_NODE;
					else
						iconType = DSA_KEY_PAIR_NODE;
				} else {
					if (isRevoked() || hasExpired())
						iconType = DSA_DISABLED_PUBLIC_KEY_NODE;
					else
						iconType = DSA_PUBLIC_KEY_NODE;
				}
				break;
			case PublicKeyAlgorithmSettings.ELGAMAL_ENCRYPT:
				if (isKeyPair()) {
					if (isRevoked() || hasExpired())
						iconType = ELGAMAL_DISABLED_KEY_PAIR_NODE;
					else
						iconType = ELGAMAL_KEY_PAIR_NODE;
				} else {
					if (isRevoked() || hasExpired())
						iconType = ELGAMAL_DISABLED_PUBLIC_KEY_NODE;
					else
						iconType = ELGAMAL_PUBLIC_KEY_NODE;
				}
				break;
		}
		return iconType;
	}
	
	/** @return the revocation signature object */
	public Signature getRevocationSignature() {
		return revocationSignature;
	}
	
	/** @param out output stream to which wrapped object should be written */
	public void writePublicKeyringPacket(OpenPGPPacketOutputStream out,
			boolean includeTrust) throws IOException, AlgorithmException {
		out.writePacket(publicKeyPacket);  // write out the public key packet
		if (includeTrust) {  // write out a trust packet
			writeTrustPacket(out);
		}
	}
	
	/** @param out output stream to which wrapped object should be written */
	public void writePrivateKeyringPacket(OpenPGPPacketOutputStream out,
			boolean includeTrust) throws IOException, AlgorithmException {
		out.writePacket(secretKeyPacket);
		if (includeTrust) {  // write out a trust packet
			writeTrustPacket(out);
		}
	}
	
	private void writeTrustPacket(OpenPGPPacketOutputStream out)
			throws IOException, AlgorithmException {
		if (keyTrust != null) {  // confirm the existing trust packet
			if (hasExpired()) {  // check if packet has expired
				byte[] trustBytes = getTrust().getTrust();
				trustBytes[0] |= TrustValues.OWNERTRUST_KEY_EXPIRED;
			}
		} else {  // make a new trust packet
			byte[] trustBytes = new byte[1];
			// flip the necessary bits
			if (this.hasPrivateKeyPart()) {
				trustBytes[0] |= TrustValues.OWNERTRUST_BUCKSTOP;
				trustBytes[0] |= TrustValues.OWNERTRUST_ULTIMATE_TRUST;
			}
			if (this.isRevoked()) {
				trustBytes[0] |= TrustValues.OWNERTRUST_KEY_REVOKED;
			}
			if (this.hasExpired()) {
				trustBytes[0] |= TrustValues.OWNERTRUST_KEY_EXPIRED;
			}
			setTrust(new TrustPacket(trustBytes));
		}
		out.writePacket(keyTrust);  // write the packet out
	}
	
	/** Method to set the parent of this node, required for tree traversal
	 * @param parentNode The ancestor node in the hierarchy 
	 */
	public void setParent(MutableTreeNode parentNode) {
		this.parentNode = parentNode;
	}
	
	/** Resets the user object of the receiver to object. */
	public void setUserObject(Object object) {
		throw new UnsupportedOperationException();
	}
	
	/** Removes the receiver from its parent. */
	public void removeFromParent() {
		MutableTreeNode node = (MutableTreeNode)getParent();
		if (node != null) {
			node.remove(this);
		}
	}

	/** @return the fingerprint, as a formatted string */
	public String getFingerprint() {
		return fingerprint;
	}
	
	/** @return the raw key ID */
	public byte[] getRawKeyID() {
		return rawKeyID;
	}

	/** @return the public key packet */
	public PublicKeyPacket getPublicKeyPacket() {
		return publicKeyPacket;
	}

	/** @return the secret key packet */
	public SecretKeyPacket getSecretKeyPacket() {
		return secretKeyPacket;
	}
}
