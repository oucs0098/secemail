package openpgp.keystore.model;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.util.Date;
import java.util.Enumeration;
import java.util.Vector;
import core.algorithmhandlers.PassPhrase;
import core.algorithmhandlers.openpgp.OpenPGPPacketOutputStream;
import core.algorithmhandlers.openpgp.packets.*;
import core.algorithmhandlers.openpgp.packets.v4signature.*;
import core.exceptions.*;
import core.keyhandlers.identifiers.OpenPGPStandardKeyIdentifier;
import javax.swing.tree.MutableTreeNode;
import javax.swing.tree.TreeNode;

import openpgp.keystore.KeyStoreTrustManager;
import openpgp.keystore.TrustValues;
import openpgp.keystore.exceptions.*;
import openpgp.keystore.util.*;

/** <p>Wrapper class representing a digital signature.</p>
 * @version $Id: Signature.java,v 1.10 2007-08-28 09:28:39 nigelb Exp $
 */
public class Signature implements ExportableKeyringPacketWrapper, Revocable,
		Expirable, KeyStoreNode {
	
	// The signature packet that this class wraps
	private SignaturePacket signaturePacket;
	// The version of the signature packet
	private int signatureVersion;
	// The type of the signature packet
	private int signatureType;
	// The 'short' key ID of the signer, extracted from the signaturePacket
	private String signingKeyShortID = "";
	// The 'long' key ID of the signer, extracted from the signaturePacket
	private String signingKeyLongID = "";
	// The 'raw' key ID in byte array form, from the signaturePacket
	private byte[] rawSigningKeyID;
	// The user ID of the signer 
	private String signingUserID = "";
	// whether there's a matching user ID
	private boolean isMatchedWithUserID = false;
	// The key that made this signature
	private PrimarySigningKey signingKey;
	// Whether this signature is a self-signature
	private boolean isSelfSignature;
	// What to display for this signature
	private String description;
	// The trust calculated for this signature
    private TrustPacket signatureTrust;
	// The parent node
    private TreeNode parentNode;
    // the signature creation date/time
    private Date creationDate;
    // whether this signature has been revoked (defaults to not revoked)
    private boolean isRevoked = false;
    // The signature revoking this signature (only non-null if this is revoked)
    private Signature revocationSignature;
    // Whether this signature has been verified
    private boolean isVerified = false;
    
    /** The main constructor
     * @param sigPkt The signature packet
     */
    public Signature(SignaturePacket sigPkt) {
        signaturePacket = sigPkt;
        try {  // set up the key IDs
        	rawSigningKeyID = signaturePacket.getKeyID();
        	signingKeyLongID = 
        		StringHelper.toHexString(signaturePacket.getKeyID());
        	signingKeyShortID = "0x" + signingKeyLongID.substring(8);
        } catch (AlgorithmException ignore) {}
        this.signingUserID = "[No User Found for Key ID " + 
        		signingKeyShortID + "]";  // assume not found, can set it later
        try {  // cache the signature version
        	signatureVersion = signaturePacket.getVersion();
        } catch (Exception ignore) {}
        // cache the signature version
        signatureType = signaturePacket.getSignatureData().getSignatureType();
    }
    
    /** @see openpgp.keystore.model.Trustable#setTrust(
     * core.algorithmhandlers.openpgp.packets.TrustPacket) 
     */
    public void setTrust(TrustPacket trustPkt) {
        signatureTrust = trustPkt;
    }
    
    /** @see openpgp.keystore.model.Trustable#getTrust() */
    public TrustPacket getTrust() {
        return signatureTrust;
    }
    
    /** @return Whether this signature has been revoked */
	public boolean isRevoked() {
		return isRevoked;
	}
    
    /** @return the revocation signature object */
	public Signature getRevocationSignature() {
		return revocationSignature;
	}

	/** @see java.lang.Object#toString() */
    public String toString() {
		if (description == null) {
			String s = "";
	    	try {
	    		if (signatureVersion == 3 || signatureVersion == 4) {
	    			//s = "V" + signatureVersion + " ";
	    			if (this.isSelfSignature())
	    				s += "Self-signature";
	    			else 
	    				//s += "Signature from " + getSigningUserID();
	    				s += getSigningUserID();
	    		} else
	    			s = "Unrecognisable Signature Version ";
	    	} catch(Exception e) {
	    		// e.g. X.509 certificate signature 
	    		// (e.g. OpenPGP doesn't recognise X.509 certs but PGP does)
	    		s = "Unrecognisable Signature";
	    	}
	    	this.description = s;
		}
    	return description;
    }
    
	/** @return the short key ID of the signing key */
	public String getSigningKeyShortID() {
		return signingKeyShortID;
	}
	
	/** @return the long key ID of the signing key */
	public String getSigningKeyLongID() {
		return signingKeyLongID;
	}
	
	/** Method to find a subpacket of a particular type in the existing
	 * signature subpackets.
	 * @param type The V4 signature subpacket type
	 * @param hashedOnly Whether to search only in the hashed subpackets
	 * @return the first signature subpacket matching the given type, or null 
	 * if not found
	 */ 
	private SignatureSubPacket findSignatureSubPacket(int type, 
			boolean hashedOnly) {
		SignatureSubPacket ssp = null;
		if (signatureVersion == 4) {
			boolean found = false;
			V4SignatureMaterial v4sm = 
				(V4SignatureMaterial)signaturePacket.getSignatureData();
			Vector hsp = v4sm.getHashedSubPackets();
			for (int i = 0; i < hsp.size() && !found; ++i) {
				SignatureSubPacket subpkt = 
						(SignatureSubPacket)hsp.elementAt(i);
				if (subpkt.getSubPacketHeader().getType() == type) {
					ssp = subpkt;
					found = true;
				}
			}
			if (!found && !hashedOnly) { // try the unhashed subpackets
				Vector usp = v4sm.getUnhashedSubPackets();
				for (int i = 0; i < usp.size() && !found; ++i) {
					SignatureSubPacket subpkt = 
							(SignatureSubPacket)hsp.elementAt(i);
					if (subpkt.getSubPacketHeader().getType() == type) {
						ssp = subpkt;
						found = true;
					}
				}
			}
		}
		return ssp;
	}
	
	/** Method to replace a subpacket of a particular type in the existing
	 * signature subpackets with another provided subpacket.
	 * @param type The V4 signature subpacket type
	 * @param substitute The subpacket to put in its place
	 * @param addIfMissing Whether to add the subpacket to the subpackets if
	 * a subpacket of the candidate type is not found to replace
	 */ 
	private void replaceSignatureSubPacket(int type,
			SignatureSubPacket substitute, boolean addIfMissing) {
		if (signatureVersion == 4) {
			boolean replaced = false;
			V4SignatureMaterial v4sm = 
				(V4SignatureMaterial)signaturePacket.getSignatureData();
			// try the hashed subpackets first
			Vector hsp = v4sm.getHashedSubPackets();
			for (int i = 0; i < hsp.size() && !replaced; ++i) {
				SignatureSubPacket subpkt = 
						(SignatureSubPacket)hsp.elementAt(i);
				if (subpkt.getSubPacketHeader().getType() == type) {
					hsp.setElementAt(substitute, i);
					replaced = true;
				}
			}
			if (!replaced) { // failing that, try the unhashed subpackets
				Vector usp = v4sm.getUnhashedSubPackets();
				for (int i = 0; i < usp.size() && !replaced; ++i) {
					SignatureSubPacket subpkt = 
							(SignatureSubPacket)hsp.elementAt(i);
					if (subpkt.getSubPacketHeader().getType() == type) {
						usp.setElementAt(substitute, i);
						replaced = true;
					}
				}
			}
			if (!replaced && addIfMissing) {  // or optionally add it
				hsp.add(substitute);
			}
		}
	}
	
	/** @return an array of preferred symmetric algorithms, in order of 
	 * preference, or null if none are found. 
	 */
	public byte[] getPreferredSymmetricAlgorithms() {
		byte[] preferred = null;
		if (this.isSelfSignature && signatureVersion == 4) {
			// look for subpacket type 11 - preferred symmetric algorithms
			SignatureSubPacket ssp = findSignatureSubPacket(11, false);
			if (ssp != null) {
				preferred = 
					((PreferredSymmetricAlgorithmSubPacket)ssp).getData();
			}
		}
		return preferred;
	}
	
	/** Method to set a list of preferred symmetric algorithms. This
	 * feature will only work for Version 4 Signatures.
	 * NOTE: NOT CURRENTLY USED. The signature needs re-signing after adding
	 * a hashed subpacket.
	 * @param prefs an array of preferred symmetric algorithms, in order of
	 * preference
	 */
	public void setPreferredSymmetricAlgorithms(byte[] prefs) {
		if (this.isSelfSignature && signatureVersion == 4) {
			// look for subpacket type 11 - preferred symmetric algorithms
			SignatureSubPacket ssp = findSignatureSubPacket(11, false);
			if (ssp != null) {
				((PreferredSymmetricAlgorithmSubPacket)ssp).setData(prefs);
			} else {
				PreferredSymmetricAlgorithmSubPacket symmetricPrefs = 
						new PreferredSymmetricAlgorithmSubPacket(prefs);
				V4SignatureMaterial sm = 
						(V4SignatureMaterial)signaturePacket.getSignatureData();
				sm.addHashedSubPacket(symmetricPrefs);
			}
		}
	}
	
	/** @return an array of preferred compression algorithms, in order of 
	 * preference, or null if none are found. 
	 */
	public byte[] getPreferredCompressionAlgorithms() {
		byte[] preferred = null;
		if (this.isSelfSignature && signatureVersion == 4) {
			if (signatureVersion == 4) {
				// look for subpacket type 22 - preferred compression algorithms
				SignatureSubPacket ssp = findSignatureSubPacket(22, false);
				if (ssp != null) {
					preferred = 
						((PreferredCompressionAlgorithmSubPacket)ssp).getData();
				}
			}
		}
		return preferred;
	}
	
	/** Method to set a list of preferred compression algorithms. This
	 * feature will only work for Version 4 Signatures.
	 * NOTE: NOT CURRENTLY USED. The signature needs re-signing after adding
	 * a hashed subpacket.
	 * @param prefs an array of preferred compression algorithms, in order of
	 * preference
	 */
	public void setPreferredCompressionAlgorithms(byte[] prefs) {
		if (this.isSelfSignature && signatureVersion == 4) {
			// look for subpacket type 22 - preferred compression algorithms
			SignatureSubPacket ssp = findSignatureSubPacket(22, false);
			if (ssp != null) {
				((PreferredCompressionAlgorithmSubPacket)ssp).setData(prefs);
			} else {
				PreferredCompressionAlgorithmSubPacket compressionPrefs = 
						new PreferredCompressionAlgorithmSubPacket(prefs);
				V4SignatureMaterial sm = 
						(V4SignatureMaterial)signaturePacket.getSignatureData();
				sm.addHashedSubPacket(compressionPrefs);
			}
		}
	}
	
	/** @return an array of preferred hash algorithms, in order of preference,
	 * or null if none are found.
	 */
	public byte[] getPreferredHashAlgorithms() {
		byte[] preferred = null;
		if (this.isSelfSignature && signatureVersion == 4) {
			// look for subpacket type 21 - preferred hash algorithms
			SignatureSubPacket ssp = findSignatureSubPacket(21, false);
			if (ssp != null) {
				preferred = ((PreferredHashAlgorithmSubPacket)ssp).getData();
			}
		}
		return preferred;
	}
	
	/** Method to set a list of preferred hash algorithms. This feature
	 * will only work for Version 4 Signatures.
	 * NOTE: NOT CURRENTLY USED. The signature needs re-signing after adding
	 * a hashed subpacket.
	 * @param prefs an array of preferred hash algorithms, in order of 
	 * preference
	 */
	public void setPreferredHashAlgorithms(byte[] prefs) {
		if (this.isSelfSignature && signatureVersion == 4) {
			// look for subpacket type 21 - preferred hash algorithms
			SignatureSubPacket ssp = findSignatureSubPacket(21, false);
			if (ssp != null) {
				((PreferredHashAlgorithmSubPacket)ssp).setData(prefs);
			} else {
				PreferredHashAlgorithmSubPacket hashPrefs = 
					new PreferredHashAlgorithmSubPacket(prefs);
				V4SignatureMaterial sm = 
					(V4SignatureMaterial)signaturePacket.getSignatureData();
				sm.addHashedSubPacket(hashPrefs);
			}
		}
	}
	
	/** Method to ascertain whether this signature should be exported when 
	 * exporting the associated signed packet. Unless marked as non-exportable
	 * it can be assumed that the packet is exportable.
	 * @return Whether or not this signature packet is exportable. 
	 */
	public boolean isExportable() {
		boolean canExport = true;  // by default we can export the signature
		if (signatureVersion == 4) {  
			// look for subpacket type 4 - exportable certification
			SignatureSubPacket ssp = findSignatureSubPacket(4, false);
			if (ssp != null) {
				canExport = ((ExportableCertification)ssp).getValue();
			}
		}
		return canExport;
	}
	
	/** This method sets a signature as exportable or non-exportable. It 
	 * should be noted that only Version 4 signatures can be marked as
	 * non-exportable. Trying to mark a Version 3 signature as non-exportable
	 * will have no effect.
	 * NOTE: NOT CURRENTLY USED. The signature needs re-signing after adding
	 * a hashed subpacket.
	 * @param exportable Whether or not this signature packet is exportable 
	 */
	public void setExportable(boolean exp) {
		if (signatureVersion == 4) {  
			// look for subpacket type 4 - exportable certification
			SignatureSubPacket ssp = findSignatureSubPacket(4, false);
			if (ssp != null) {
				((ExportableCertification)ssp).setValue(exp);
			} else {
				ExportableCertification ec = new ExportableCertification(exp);
				V4SignatureMaterial sm = 
					(V4SignatureMaterial)signaturePacket.getSignatureData();
				sm.addHashedSubPacket(ec);
			}
		}
	}
	
	/** Method to ascertain whether this signature should be revoked. Unless 
	 * marked as non-revocable it can be assumed that the packet is revocable.
	 * This method does not solely rely on the RevocableSubPacket - it also
	 * checks that the private signing key is locally available (in the keyring)
	 * before confirming that the signature is revocable. 
	 * @return Whether or not this signature packet is revocable. 
	 */
	public boolean isRevocable() {
		boolean canRevoke = true;  // by default we can revoke the signature
		if (signatureVersion == 4) {  
			// look for subpacket type 7 - revocable
			SignatureSubPacket ssp = findSignatureSubPacket(7, false);
			if (ssp != null) {
				canRevoke = ((RevocableSubPacket)ssp).getValue();
			}
		}
		if (canRevoke) {  // check that the private signing key is available
			if (signingKey == null || !signingKey.hasPrivateKeyPart()) {
				canRevoke = false;
			}
		}
		return canRevoke;
	}
	
	// used to store trust signature values.
	private int trustDepth = 0;
	private int trustLevel = 0;
	
	/** Method to find out whether this signature is a trust signature.
	 * @return Whether or not this is a trust signature.
	 */
	public boolean isTrustSignature() {
		boolean isTrustSig = false;
		if (signatureVersion == 4) {  // find subpacket type 5 - trust signature
			SignatureSubPacket ssp = findSignatureSubPacket(5, false);
			if (ssp != null) {
				isTrustSig = true;
				if (signingKey != null && !signingKey.isRevoked()) {
					trustDepth = ((TrustSignatureSubPacket)ssp).getDepth();
					if (trustDepth > 2) trustDepth = 2;  // PGP sets this higher
					trustLevel = ((TrustSignatureSubPacket)ssp).getAmount();
					if (trustLevel > 0) {
						if (trustLevel < 120)
							trustLevel = 60;
						else
							trustLevel = 120;
					}
				}
			}
		}
		return isTrustSig;
	}
	
	/** Method to get the signature trust depth. This should be called
	 * after getting a 'true' return value from  'isTrustSignature()'
	 * @return The trust depth of this signature, or 0 if no trust depth applies
	 */
	public int getTrustSignatureDepth() {
		return trustDepth;
	}
	
	/** Method to get the signature trust amount. This should be called
	 * after getting a 'true' return value from  'isTrustSignature()'
	 * @return The trust amount of this signature, 0 for no trust, 60 for partial
	 * trust, 120 for complete trust
	 */
	public int getTrustSignatureAmount() {
		return trustLevel;
	}
	
	/** Implementation of the Revocable interface method of the same name.  
	 * This method sets the status of this certification signature to revoked.
	 * This method is normally called from the UserID object that this 
	 * signature is attached to, because this method applies to a revoked 
	 * signature. Subkey objects and PrimarySigningKey objects, which can also
	 * be revoked, will have their own version of this method.
	 * @param signature The revocation signature
	 */
	public void setRevocationSignature(Signature signature) {
		// Initial validation:
		// The certification signature should be issued by the same key that
		// issued the revoked signature (or an authorised revocation key - this
		// is currently unimplemented). It should also have a later creation 
		// date than that certificate. The program cannot fully validate 
		// signatures until the keyring is fully loaded, and all signing keys 
		// are available, so the validation step should be a separate one. If
		// the initial tests are passed, the signature is set as revoked.
		// The subsequent validation will be able to unrevoke the certification
		// signature if the revocation signature subsequently turns out to be 
		// not valid.
		if (signature.getSigningKeyLongID().equals(getSigningKeyLongID()) && 
				signature.getCreationDate().after(getCreationDate())) {
			this.revocationSignature = signature;
			this.isRevoked = true;
		} else {
			// Ignore the revocation, it failed the initial revocation test
			debug.Debug.println(1, "xxx Revocation signature failed the " +
					"validity test. Revocation signature made on " + 
					signature.getCreationDate() + ", cert signature made on " + 
					getCreationDate() + ", revocation signature key ID = " + 
					signature.getSigningKeyLongID() + ", cert signature key " +
					"ID = " + getSigningKeyLongID());
		}
	}
	
	/** method to write a key in the format required for signatures.
	 * @param keyPacket The key packet to be included
	 * @param stream The stream to which the packet will be written
	 */
	static void writeKey(PublicKeyPacket keyPacket, OutputStream stream)
			throws AlgorithmException, IOException {
		byte[] packetBody = keyPacket.encodePacketBody();
		stream.write(0x99); // constant required for a hashed key
		stream.write((packetBody.length >> 8) & 0xff);
		stream.write(packetBody.length & 0xff);
		stream.write(packetBody);
	}

	/** method to write a user id in the format required for signatures.
	 * @param keyPacket The key packet to be included
	 * @param stream The stream to which the packet will be written
	 */
	static void writeUserID(OpenPGPStandardKeyIdentifier id,
			OutputStream stream) throws KeyHandlerException, IOException {
		byte[] userIDBody = id.getDefaultID();
		stream.write(0xb4); // constant required for V4 User ID certification
		stream.write((userIDBody.length >> 24) & 0xff);
		stream.write((userIDBody.length >> 16) & 0xff);
		stream.write((userIDBody.length >> 8) & 0xff);
		stream.write(userIDBody.length & 0xff);
		stream.write(userIDBody);
	}
	
	/** method to write a user id in the format required for signatures.
	 * @param keyPacket The key packet to be included
	 * @param stream The stream to which the packet will be written
	 */
	static void writeUserAttribute(UserAttributePacket attributePacket,
			OutputStream stream) throws AlgorithmException, IOException {
		byte[] userAttributeBody = attributePacket.encodePacketBody();
		stream.write(0xd1); // constant required for V4 User Attribute
		stream.write((userAttributeBody.length >> 24) & 0xff);
		stream.write((userAttributeBody.length >> 16) & 0xff);
		stream.write((userAttributeBody.length >> 8) & 0xff);
		stream.write(userAttributeBody.length & 0xff);
		stream.write(userAttributeBody);
	}
	
	/** Method to construct the data used in a certification (or certification
	 * revocation) signature
	 * @return The data in a byte array form
	 * @throws Exception
	 */
	private byte[] getCertificationSignatureData() throws AlgorithmException,
			IOException, KeyHandlerException {
		byte[] dataToSign = null;
		// get the user ID data
		UserObject userObject = (UserObject)this.getParent();
		if (userObject instanceof UserID) {
			UserID uid = (UserID)userObject;
			OpenPGPStandardKeyIdentifier ski = uid.getStandardKeyIdentifier();
			// get the certified key data
			PrimarySigningKey certifiedKey = 
					(PrimarySigningKey)this.getParent().getParent();
			// construct the data
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			writeKey(certifiedKey.publicKeyPacket, baos);
			writeUserID(ski, baos);
			dataToSign = baos.toByteArray();
		} else if (userObject instanceof UserAttribute) {
			UserAttribute ua = (UserAttribute)userObject;
			// get the certified key data
			PrimarySigningKey certifiedKey = 
					(PrimarySigningKey)this.getParent().getParent();
			// construct the data
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			writeKey(certifiedKey.publicKeyPacket, baos);
			writeUserAttribute((UserAttributePacket)ua.userPacket, baos);
			dataToSign = baos.toByteArray();
		}
		return dataToSign;
	}
	
	/** @see openpgp.keystore.model.Revocable#revoke() */
	public void revoke(PrimarySigningKey revoker, PassPhrase passPhrase, int reason)
			throws RevocationException, KeyMismatchException {

		if (this.isRevoked) {
			throw new RevocationException("Signature is already revoked");
		}
		// check primary key ID matches key id of key that made this signature
		if (!revoker.getLongKeyID().equals(getSigningKeyLongID())) {
			throw new KeyMismatchException("Can't revoke certificate made by " +
					"key " + getSigningKeyShortID() + " with signing key " +
					revoker.getShortKeyID());
		}
		// revoke the signature
		try {
			// decrypt the key data
			revoker.secretKeyPacket.decryptKeyData(
					passPhrase.getPassphraseData());
			// now the data is decrypted the private key is accessible
			PrivateKey privateKey = 
					revoker.secretKeyPacket.getKeyData().getPrivateKey();
			
			// get the same data as the certification was made over
			byte[] dataToSign = getCertificationSignatureData();
			
			V4SignatureMaterial signatureMaterial = new V4SignatureMaterial(
		        	privateKey, // signing key
		            0, // revocation does not expire
		            revoker.secretKeyPacket.getKeyID(), // the key ID
		            SignaturePacket.CERT_REVOCATION, // signature type
		            revoker.secretKeyPacket.getAlgorithm(), // key algorithm
		            2, // hash algorithm - currently defaulting to SHA1
		            dataToSign // the data to sign
		        );
			
			Signature revocation = new Signature(
					new SignaturePacket(signatureMaterial));
			// set up the trust - must be a new trust packet
			byte[] trustBytes = new byte[1];
			trustBytes[0] = revoker.getTrust().getTrust()[0];
			revocation.setTrust(new TrustPacket(trustBytes));
			
			// apply the revoked trust value (not trusted) and set as revoked
			KeyStoreTrustManager.applyTrust(this, 
					TrustValues.OWNERTRUST_NOT_USUALLY_TRUSTED);
			((UserObject)getParent()).addSignature(revocation);
		} catch(Exception e) {
			e.printStackTrace();
			throw new RevocationException(e.getMessage());
		}
	}
	
	/** Method to verify a revocation signature. This method requires the 
	 * public key corresponding to the private key that was used to create the
	 * revocation signature, for verification. 
	 * @param key The primary signing key
	 * @return true if the revocation signature is valid, false if not valid
	 */
	public boolean verifyRevocationSignature(PrimarySigningKey revoker)
			throws RevocationException, KeyMismatchException {
		// The signature is computed over the same data as the object that
		// it revokes. If it fails the verification, unset the revoked flag, 
		// and discard the revocation signature.
		boolean isValidSignature = false;
		if (this.isRevoked && getRevocationSignature() != null) {
			debug.Debug.println(1, "Verifying revocation signature for " +
					"signature certifying '" + 
					((UserObject)getParent()).toString() + "'");
			
			try {
				// retrieve the revocation signature to verify
				Signature revocationSig = getRevocationSignature();
				// make sure the signing key is correct
				if (!revoker.getLongKeyID().equals(
						revocationSig.getSigningKeyLongID())) { 
					throw new KeyMismatchException(
						"The key ID of the signing key does not match the " +
						"signers key ID on the signature"); 
				}
				// get the same data as the certification/revocation was over
				byte[] dataToVerify = getCertificationSignatureData();
				// get the signature material from the signature
				SignatureMaterial sm = signaturePacket.getSignatureData();
				// verify the revocation signature
				isValidSignature = sm.verify(
						revoker.getPublicKeyPacket().getKeyData().getPublicKey(),
						dataToVerify);
				// if the signature is valid, mark it as verified
				if (isValidSignature) {
					revocationSig.setVerified(isValidSignature);
				} else {
					debug.Debug.println(1, "Discarding invalid certification " +
							"revocation signature on signature by key ID '" + 
							this.getSigningKeyShortID() + "' certifying " +
							"'" + ((UserObject)getParent()).toString() + "'");
					this.isRevoked = false;
					this.revocationSignature = null;
				}
			} catch(AlgorithmException e) {
				throw new RevocationException(e.getMessage());
			} catch(KeyHandlerException e) {
				throw new RevocationException(e.getMessage());
			} catch(IOException e) {
				throw new RevocationException(e.getMessage());
			}
		} else {
			throw new RevocationException("This signature is not revoked");
		}
		return isValidSignature;
	}
	
	/** Method to verify a revocation signature. This method requires the 
	 * public key corresponding to the private key that was used to create the
	 * revocation signature, for verification. 
	 * @param key The primary signing key
	 * @return true if the revocation signature is valid, false if not valid
	 */
	public boolean verifyCertificationSignature(PrimarySigningKey signer)
			throws CertificationException, KeyMismatchException {
		// The signature is computed over the same data as the object that
		// it revokes. If it fails the verification, unset the revoked flag, 
		// and discard the revocation signature.
		boolean isValidSignature = false;
		PrimarySigningKey psk = (PrimarySigningKey)getParent().getParent();
		debug.Debug.println(1, "Verifying certification signature " +
				"binding key ID " + psk.getShortKeyID() + " with '" +
				((UserObject)getParent()).toString() + "'");
		if (!signer.getLongKeyID().equals(getSigningKeyLongID())) { 
			throw new KeyMismatchException("The key ID of the signing key " +
					"does not match the signers key ID on the signature"); 
		}
		int type = signaturePacket.getSignatureData().getSignatureType();
		if (type >= SignaturePacket.GENERIC_UID
				&& type <= SignaturePacket.POSITIVE_UID) {
			try {
				// get the same data as the certification/revocation was over
				byte[] dataToVerify = getCertificationSignatureData();
				// verify the revocation signature
				isValidSignature = signaturePacket.getSignatureData().verify(
						signer.getPublicKeyPacket().getKeyData().getPublicKey(),
						dataToVerify);
				// if the signature is valid, mark it as verified
				if (isValidSignature) {
					setVerified(isValidSignature);
				}
			} catch(Exception e) {
				throw new CertificationException(e.getMessage());
			}
		} else {
			throw new CertificationException(
					"This signature is not a certification signature");
		}
		return isValidSignature;
	}

	/** Method to find out whether the key flags carried by this signature 
	 * state that the associated signing key can certify other keys. The key
	 * flags packet can occur in self-signatures or in certification signatures
	 * @return true if the signing key can certify other keys
	 */
	public boolean canCertifyKeys() {
		boolean canCertify = false;
		if (signatureVersion == 4) {
			// look for subpacket type 27 - key flags
			SignatureSubPacket ssp = findSignatureSubPacket(27, false);
			if (ssp != null) {
				canCertify = ((KeyFlagsSubPacket)ssp).getMayCertifyKeyFlag();
			}
		}
		return canCertify;
	}
	
	/** Whether this self-signature states that the user ID it is associated
	 * with is the primary user ID for the primary signing key.
	 * @return Whether or not the user this signature packet is associated with
	 * is the main user ID for the top-level signing key. 
	 */
	public boolean isPrimaryUserID() {
		boolean isPrimary = false;
		if (this.isSelfSignature && signatureVersion == 4) {
			// look for subpacket type 25 - primary user ID
			SignatureSubPacket ssp = findSignatureSubPacket(25, false);
			if (ssp != null) {
				isPrimary = ((PrimaryUserIDSubPacket)ssp).getValue();
			}
		}
		return isPrimary;
	}
	
	/** Marks the user ID that this self-signature certifies as the primary
	 * user ID for the associated primary signing key.
	 * This will only affect version 4 self-signatures.
	 * NOTE: NOT CURRENTLY USED. The signature needs re-signing after adding
	 * a hashed subpacket.
	 * @param Whether or not the user this signature packet is associated with
	 * is the main user ID for the top-level signing key. 
	 */
	public void setPrimaryUserID(boolean isPrimary) {
		if (this.isSelfSignature && signatureVersion == 4) {
			// look for subpacket type 25 - primary user ID
			SignatureSubPacket ssp = findSignatureSubPacket(25, false);
			if (ssp != null) {  // primary user id subpacket found
				((PrimaryUserIDSubPacket)ssp).setValue(isPrimary);
			} else {  // add a new one
				PrimaryUserIDSubPacket p = new PrimaryUserIDSubPacket(isPrimary);
				V4SignatureMaterial sm = 
						(V4SignatureMaterial)signaturePacket.getSignatureData();
				sm.addHashedSubPacket(p);
			}
		}
	}
	
	/** Method to set the parent of this node, required for tree traversal
	 * @param parentNode The ancestor node in the hierarchy 
	 */
	void setParent(TreeNode parentNode) {
		this.parentNode = parentNode;
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

	/** @return the signing User ID */
	public String getSigningUserID() {
		return signingUserID;
	}
	
	/** @param signingUserID the signing User ID to set */
	public void setSigningUserID(PrimarySigningKey signingKey) {
		signingUserID = signingKey.getPrimaryEmailAddress();
		isMatchedWithUserID = true;
		this.signingKey = signingKey;  // for isRevocable() checks
	}
	
	/** @return whether this signature is a self-signature */
	public boolean isSelfSignature() {
		return isSelfSignature;
	}

	/** Method to set whether or not this is a self signature. This should be
	 * set, once, at the point that the signature is added to the user binding.
	 * @param isSelfSignature whether or not this is a self signature 
	 */
	void setSelfSignature(boolean isSelfSignature) {
		this.isSelfSignature = isSelfSignature;
	}

	/** @see openpgp.keystore.model.KeyStoreNode#getIconType() */
	public int getIconType() {
		if (this.isRevoked() || this.hasExpired())
			return DISABLED_SIGNATURE_NODE;
		else
			return SIGNATURE_NODE;
	}

	/** @param out output stream to which wrapped object should be written */
	public void writePublicKeyringPacket(OpenPGPPacketOutputStream out,
			boolean includeTrust) throws IOException, AlgorithmException {
		out.writePacket(signaturePacket);
		if (includeTrust && signatureTrust != null) 
			out.writePacket(signatureTrust);
	}
	
	/** @param out output stream to which wrapped object should be written */
	public void writePrivateKeyringPacket(OpenPGPPacketOutputStream out,
			boolean includeTrust) throws IOException, AlgorithmException {
		// private export for this class is the same as public export
		this.writePublicKeyringPacket(out, includeTrust);
	}

	/** @return the date and time that this signature was created, or null if
	 * it cannot be found.
	 */
	public Date getCreationDate() {
		if (creationDate == null) {
			switch (signatureVersion) {
				case 3:
					V3SignatureMaterial v3sm =
						(V3SignatureMaterial)signaturePacket.getSignatureData();
					creationDate = new Date(v3sm.getCreateDate() * 1000);
					break;
				case 4:
					// look for subpacket type 2 - signature creation time
					SignatureSubPacket ssp = findSignatureSubPacket(2, true);
					if (ssp != null) {
						creationDate = 
							((SignatureCreationTimeSubPacket)ssp).getTime();
					}
					break;
			}
		}
		return creationDate;
	}
	
	/** Method to retrieve the signature expiration time. 
	 * If the subpacket does not exist it is assumed that the signature 
	 * does not expire.
	 * @return the number of seconds after the creation time that this 
	 * signature expires, or 0 if the signature does not expire.
	 */
	protected long getExpirationTime() {
		long expires = 0L;
		if (signatureVersion == 4) {
			// look for subpacket type 3 - signature expiration time
			SignatureSubPacket ssp = findSignatureSubPacket(3, false);
			if (ssp != null) {
				expires = ((SignatureExpirationTimeSubPacket)ssp).getTimeLong();
			}
		}
		return expires;
	}
	
	/** Method to retrieve the signature expiration date. 
	 * If the subpacket does not exist it is assumed that the signature 
	 * does not expire, and null is returned
	 * @return the date that this signature expires, or null if it doesn't.
	 */
	public Date getExpirationDate() {
		Date expiryDate = null;
		long expTime = getExpirationTime();
		if (expTime > 0) { // an expiry date exists
			expiryDate = new Date(getCreationDate().getTime() + (expTime * 1000));
		}
		return expiryDate;
	}
	
	/** Method to retrieve the key expiration time.
	 * If the subpacket does not exist it is assumed that the key 
	 * does not expire.
	 * @return the number of seconds after the key creation time that this 
	 * key expires, or 0 if it does not expire.
	 */
	protected long getKeyExpirationTime() {
		long expires = 0L;
		if (this.isSelfSignature && signatureVersion == 4) {
			// look for subpacket type 9 - key expiration time
			SignatureSubPacket ssp = findSignatureSubPacket(9, false);
			if (ssp != null) {
				expires = ((KeyExpirationTimeSubPacket)ssp).getTimeLong();
			}
		}
		return expires;
	}
	
	/** Method to set the key expiry time. The creation time will only be set
	 * if this is a version 4 self-signature. 
	 * NOTE: NOT CURRENTLY USED. The signature needs re-signing after adding
	 * a hashed subpacket.
	 * @param secondsAfterCreationTime the number of seconds after the 
	 * signature creation time that this signature expires
	 */
	public void setKeyExpirationTime(long secondsAfterCreationTime) {
		if (this.isSelfSignature && signatureVersion == 4) {
			if (secondsAfterCreationTime < 0) secondsAfterCreationTime = 0;
			KeyExpirationTimeSubPacket ketsp = 
				new KeyExpirationTimeSubPacket(secondsAfterCreationTime);
			replaceSignatureSubPacket(9, ketsp, true);
		}
	}
	
	/** @return Whether this signature has expired */
	public boolean hasExpired() {
		boolean isExpired = false;
		Date expiryDate = getExpirationDate();
		if (expiryDate != null) {
			Date currentDate = new Date();
			if (currentDate.compareTo(expiryDate) > 0) {
	        	isExpired = true;
	        }
		}
		return isExpired;
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

	/** Removes the receiver from its parent. */
	public void removeFromParent() {
		MutableTreeNode node = (MutableTreeNode)getParent();
		if (node != null) {
			node.remove(this);
		}
	}

	/** Sets the parent of the receiver to newParent. */
	public void setParent(MutableTreeNode newParent) {
		this.parentNode = newParent;
	}

	/** Resets the user object of the receiver to object. */
	public void setUserObject(Object object) {
		throw new UnsupportedOperationException();
	}

	/** @return the signature type */
	public int getSignatureType() {
		return signatureType;
	}

	/** @return the raw signing key ID */
	public byte[] getRawSigningKeyID() {
		return rawSigningKeyID;
	}

	/** @return Whether this signature is verified as valid */
	public boolean isVerified() {
		return isVerified;
	}

	/** @param isVerified Whether this signature is verified as valid */
	protected void setVerified(boolean isVerified) {
		this.isVerified = isVerified;
	}

	/** @return the signature packet  */
	protected SignaturePacket getSignaturePacket() {
		return signaturePacket;
	}

	/** @return whether or not this signature has its signers user ID */
	public boolean isMatchedWithUserID() {
		return isMatchedWithUserID;
	}
    
}
