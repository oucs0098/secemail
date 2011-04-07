package openpgp.keystore;

import java.util.Iterator;
import java.util.Hashtable;
import java.util.Map;
import java.util.List;
import java.util.ArrayList;

import openpgp.keystore.model.*;
import core.algorithmhandlers.openpgp.packets.*;
import core.exceptions.*;

/** <p>Class to manage the trust values and calculations for the key store.</p>
 * <p>This process is based on the trust calculation process for PGP 2.6, but
 * is not identical, since OpenPGP keys, and especially V4 keys, are not the
 * same - subkeys are now also included in the trust calculation.</p>
 * @version $Id: KeyStoreTrustManager.java,v 1.16 2007-08-27 20:38:28 nigelb Exp $
 */
public class KeyStoreTrustManager implements TrustValues {
	
	/** This variable holds the number of complete signatures required to make
	 * a user binding legitimate. The default value is 1.
	 */
	private int completesNeeded;
	
	/** This variable holds the number of marginal signatures required to make
	 * a user binding legitimate. The default value is 2.
	 */
	private int marginalsNeeded;
	
	/** The default no-argument constructor */
	public KeyStoreTrustManager() {
		this(1, 2);
	}
	
	/** The main constructor. This class should be ready for when and if the
	 * two values are parameterised in the GUI.
	 * @param completesNeeded the number of complete signatures required to make
	 * a user binding legitimate
	 * @param marginalsNeeded the number of marginal signatures required to make
	 * a user binding legitimate
	 */
	public KeyStoreTrustManager(int completesNeeded, int marginalsNeeded) {
		super();
		this.completesNeeded = completesNeeded;
		this.marginalsNeeded = marginalsNeeded;
	}

	/** Method to apply an owner trust value to a primary key. The owner trust
	 * value reflects the amount of trust that the caller has in the owner of
	 * the primary key to authenticate other keyholders reliably. The definition
	 * of values for the owner trust is implementation specific.
	 * @param primaryKey The primary key to which the owner trust value is to be
	 * applied
	 * @param ownerTrust The amount of owner trust to be applied to the key 
	 * owner
	 */
	public static void applyTrust(PrimarySigningKey primaryKey, int ownerTrust) {
		
		// validate ownertrust
		if (ownerTrust < OWNERTRUST_UNDEFINED || 
				ownerTrust > OWNERTRUST_ULTIMATE_TRUST || 
				ownerTrust == OWNERTRUST_RESERVED_3 || 
				ownerTrust == OWNERTRUST_RESERVED_4) {
			// do nothing
		} else {		
			try {
				TrustPacket packet = primaryKey.getTrust();
				
				if (packet == null) {  // make a new trust packet
					byte[] trustBytes = new byte[1];
					packet = new TrustPacket(trustBytes);
					primaryKey.setTrust(packet);
				}
				
				// unset the old trust bytes and set the new trust bytes
				packet.getTrust()[0] &= OWNERTRUST_MASK_ALLTRUST;
				packet.getTrust()[0] |= (byte)(ownerTrust & 0xFF);
				
				// set the buckstop bit if this key is in the secret keyring
				if (primaryKey.isKeyPair()) {
					packet.getTrust()[0] |= OWNERTRUST_BUCKSTOP;
				}
			} catch(AlgorithmException e) {e.printStackTrace();}
		}
	}
	
	/** Method to apply the trust bits to the user binding (i.e. set the key
	 * legitimacy value)
	 * @param userObject The user object for applying the trust value to
	 * @param keyLegitimacy The trust value
	 */
	private static void applyTrust(UserObject userObject, int keyLegitimacy) {
		
		try {
			TrustPacket packet = userObject.getTrust();
			
			if (packet == null) {  // make a new trust packet
				byte[] trustBytes = new byte[1];
				packet = new TrustPacket(trustBytes);
				userObject.setTrust(packet);
			} else {
				// unset the old trust bits
				packet.getTrust()[0] &= KEYLEGIT_MASK_ALLTRUST;
			}
			
			// set the new trust bits
			packet.getTrust()[0] |= (byte)(keyLegitimacy & 0xFF);
			
		} catch(AlgorithmException e) {e.printStackTrace();}
	}
	
	/** Method to apply the trust bits to the signature (i.e. set the signature
	 * trust value)
	 * @param signature The signature for applying the trust value to
	 * @param signatureTrust The trust value
	 */
	public static void applyTrust(Subkey subkey, int subkeyTrust) {
		
		try {
			TrustPacket packet = subkey.getTrust();
			
			if (packet == null) {  // make a new trust packet
				byte[] trustBytes = new byte[1];
				packet = new TrustPacket(trustBytes);
				subkey.setTrust(packet);
			} else {
				// unset the old trust bits
				packet.getTrust()[0] &= OWNERTRUST_MASK_ALLTRUST;
			}
			
			// set the new trust bits
			packet.getTrust()[0] |= (byte)(subkeyTrust & 0xFF);
			
		} catch(AlgorithmException e) {e.printStackTrace();}
	}
	
	/** Method to apply the trust bits to the signature (i.e. set the signature
	 * trust value)
	 * @param signature The signature for applying the trust value to
	 * @param signatureTrust The trust value
	 */
	public static void applyTrust(Signature signature, int signatureTrust) {
		
		try {
			TrustPacket packet = signature.getTrust();
			
			if (packet == null) {  // make a new trust packet
				byte[] trustBytes = new byte[1];
				packet = new TrustPacket(trustBytes);
				signature.setTrust(packet);
			} else {
				// unset the old trust bits
				packet.getTrust()[0] &= SIGTRUST_MASK_ALLTRUST;
			}
			
			// set the new trust bits
			packet.getTrust()[0] |= (byte)(signatureTrust & 0xFF);
			
		} catch(AlgorithmException e) {e.printStackTrace();}
	}

	/** Method to clear the trust values. Note that for keys that are in both
     * the private and public keyring, the ultimate trust values should not be
     * cleared. This method should then recalculate the trust values based on
     * the ultimately trusted keys (probably be calling the 'refreshTrust'
     * method directly).
     * @param keyStore The key store containing the keys whose trust values will
     * be cleared and recalculated 
	 */
	public void clearTrust(KeyStore keyStore) {
		// unset the public-keyring-only primary key trust values
		for (Iterator it = keyStore.getKeyIterator(); it.hasNext();) {
			PrimarySigningKey pk = (PrimarySigningKey)it.next();
			if (!pk.isKeyPair()) applyTrust(pk, OWNERTRUST_UNDEFINED);
		}
		refreshTrust(keyStore);
	}
	
	/** Method to initialise the subkey trust packets
	 * @param subkey The subkey to initialise with clear trust packets 
	 */
	public static void applyClearTrust(Subkey subkey) {
		try {
			// reset the subkey trust values
			applyClearTrustPacket(subkey);
			for (Iterator it = subkey.getSignatureIterator(); it.hasNext();) {
				Signature sig = (Signature)it.next();
				applyClearTrustPacket(sig);
			}
		} catch(AlgorithmException e) {e.printStackTrace();}
	}

	/** Hashtable for use by the refreshTrust() and addSignatures() methods 
	 * The hashtable keys are the long key IDs - each value object is a List
	 * object containing Signature objects made by the key denoted by the long
	 * key ID. Built in step 1 of refreshTrust(), used in step 2 of 
	 * refreshTrust(). Also used in the processTrustSignatureChain() method.
	 */
	private Map sigMap = new Hashtable();
	
	/** method to add signatures from the signable object to the hashtable */ 
	private void addSignatures(Signable signable) {
		List list;
		// Iterate over the signatures for this signable object
		for (Iterator it = signable.getSignatureIterator(); it.hasNext();) {
			Signature sig = (Signature)it.next();
			// add the signature to the hashtable
			if (sigMap.containsKey(sig.getSigningKeyLongID())) {
				// there's already at least one signature
				list = (List)sigMap.get(sig.getSigningKeyLongID());
			} else {
				// put a new key/list combination in the hashtable
				list = new ArrayList();
				sigMap.put(sig.getSigningKeyLongID(), list);
			}
			list.add(sig);
		}
	}
	
	/** Method to convert the signature trust value to the trust byte value.
	 * Values are 60 for partial trust and 120 for always trusted.
	 * @param trustAmount The trust amount, from the trust signature. Can be
	 * 60 or 120. Any other value is converted to 0 (unknown trust)
	 * @return The trust byte value
	 */
	private byte convertTrustSignatureAmount(int trustAmount) {
		byte trustValue = 0;
		switch (trustAmount) {
			case 120:
				trustValue = OWNERTRUST_ALWAYS_TRUSTED;
				break;
			case 60:
				trustValue = OWNERTRUST_USUALLY_TRUSTED;
				break;
			default:
		}
		return trustValue;
	}
	
	/** Method to process a chain of trust signatures. When processed, the
	 * signature will be removed from the collection. This prevents the
	 * signature being processed twice in separate passes.
	 * @param signer The signing key for this signature
	 * @param signature The trust signature being processed
	 * @param maxDepth The maximum depth to process the trust
	 * @param maxTrust The maximum trust to allocate
	 */
	private void processTrustSignatureChain(PrimarySigningKey signer, 
			Signature signature, int maxDepth, byte maxTrust) {
		if (maxDepth > 0) {
			PrimarySigningKey psk = 
					(PrimarySigningKey)signature.getParent().getParent();
			List sigList = (List)sigMap.get(psk.getLongKeyID());
			if (psk.isRevoked()) {  // go no further in the signature chain
				// set signatures to 'not trusted', remove them from signature map
				if (sigList != null) {
					for (Iterator it = sigList.iterator(); it.hasNext();) {
						Signature s = (Signature)it.next();
						applyTrust(s, OWNERTRUST_NOT_USUALLY_TRUSTED);
					}
					sigMap.remove(psk.getLongKeyID());
				}
			} else {
				if (sigList != null) {
					for (Iterator it = sigList.iterator(); it.hasNext();) {
						Signature s = (Signature)it.next();
						if (s.isSelfSignature()) 
							continue;  // ignore self-certifications
						int sigType = s.getSignatureType();
						if (sigType < SignaturePacket.GENERIC_UID ||
								sigType > SignaturePacket.POSITIVE_UID)
							continue;  // ignore non-certifications
						// process certification signatures
						if (!s.isRevoked() && s.isVerified()) {
							byte trustByte = maxTrust;
							// recurse for trust signatures
							if (s.isTrustSignature()) {
								// got a trust signature
								trustByte = convertTrustSignatureAmount(
										s.getTrustSignatureAmount());
								// don't let trust level exceed maximum
								if (trustByte > maxTrust) 
									trustByte = maxTrust;
								// recurse if the trust signature does
								if (s.getTrustSignatureDepth() > 0) {
									processTrustSignatureChain(
											psk, s, maxDepth-1, trustByte);
								}
							}
							byte[] trustBytes = psk.getTrust().getTrust();
							byte signerTrust = (byte)(trustBytes[0] & 
									OWNERTRUST_ULTIMATE_TRUST);
							if (signerTrust > trustByte) 
								trustByte = signerTrust;
							applyTrust(s, trustByte);
						} else {
							// apply 'not trusted' to signature
							applyTrust(s, OWNERTRUST_NOT_USUALLY_TRUSTED);
						}
						// remove from underlying list (only process once)
						it.remove();
					}
				}
			}
		} else {
			// treat as a normal signature, allow fall-through
		}
	}
	
	// 'bindings' and 'subkeys' are object-scope references to avoid the 
	// repeated object creation overhead that would be incurred if they were
	// local variables. Both are used in the refreshTrust() method.
	
	/** Contains User Objects. Built in step 1, used in step 3. */
	private List bindings = new ArrayList();
	
	/** Contains Subkey objects. Built in step 1, used in step 4. */
	private List subkeys = new ArrayList();
	
	/** Method to update the signature trust and key legitimacy values across
     * all keys in the key store.
     * @param keyStore The key store containing the keys whose trust values will
     * be recalculated
	 */
	public void refreshTrust(KeyStore keyStore) {
		sigMap.clear();
		bindings.clear();
		subkeys.clear();
		
		// try and validate any unvalidated signatures before refreshing trust,
		// to be sure that any revoked keys really are genuinely revoked
		KeyStoreValidator.validateSignatures(keyStore);
		
		// Step 1: Build the signature map and the user bindings list
		for (Iterator keys = keyStore.getKeyIterator(); keys.hasNext();) {
			// first, add any signatures following the primary key ...
			PrimarySigningKey pk = (PrimarySigningKey)keys.next();
			addSignatures(pk);
			
			// next, add any signatures from the subkeys ...
			for (Iterator it = pk.getSubkeyIterator(); it.hasNext();) {
				Subkey sk = (Subkey)it.next();
				addSignatures(sk);
				// add the subkey to the subkeys list ready for step 4
				subkeys.add(sk);
			}
			
			// then add any signatures from the user IDs ...
			for (Iterator it = pk.getUserIDIterator(); it.hasNext();) {
				UserID uid = (UserID)it.next();
				addSignatures(uid);
				// add the user bindings to the bindings list ready for step 3
				bindings.add(uid);
			}
			
			// finally, add any signatures from the user attributes ...
			for (Iterator it = pk.getUserAttributeIterator(); it.hasNext();) {
				UserAttribute uattr = (UserAttribute)it.next();
				addSignatures(uattr);
				// add the user bindings to the bindings list ready for step 3
				bindings.add(uattr);
			}
		}
		
		// Step 2 part 1: process any signature trust chains emanating from the
		// user's keys
		for (Iterator keys = keyStore.getKeyIterator(); keys.hasNext();) {
			PrimarySigningKey psk = (PrimarySigningKey)keys.next();
			// only process non-revoked user keys
			if (psk.hasPrivateKeyPart() && !psk.isRevoked()) {
				List sigList = (List)sigMap.get(psk.getLongKeyID());
				if (sigList != null) {
					for (Iterator it = sigList.iterator(); it.hasNext();) {
						Signature sig = (Signature)it.next();
						// if it's a trust signature, process the chain
						if (sig.isTrustSignature()) {
							byte[] trustBytes = psk.getTrust().getTrust();
							byte trustByte = convertTrustSignatureAmount(
									sig.getTrustSignatureAmount());
							byte signerTrust = (byte)(trustBytes[0] & 
									OWNERTRUST_ULTIMATE_TRUST);
							// allow the trust value set in the app to
							// override the signature trust
							if (signerTrust < trustByte) 
								trustByte = signerTrust;
							// process the trust signature chain
							processTrustSignatureChain(psk, sig, 
									sig.getTrustSignatureDepth(), trustByte);
						}
					}
				}
			}
		}
		
		// Step 2 part 2: for each signing key ID, copy owner trust to 
		// signature trust
		// UNLESS that signature was processed in step 2 part 1, is revoked or
		// could not be verified
		for (Iterator keys = keyStore.getKeyIterator(); keys.hasNext();) {
			PrimarySigningKey pk = (PrimarySigningKey)keys.next();
			byte[] trustBytes = pk.getTrust().getTrust();
			
			// get the collected signatures for this key using the long key ID
			List sigList = (List)sigMap.get(pk.getLongKeyID());
			if (sigList != null) {
				for (Iterator it = sigList.iterator(); it.hasNext();) {
					Signature sig = (Signature)it.next();
					if (sig.isRevoked() || !sig.isVerified()) {
						applyTrust(sig, OWNERTRUST_NOT_USUALLY_TRUSTED);
					} else {
						// get trust value
						byte trust = (byte)(trustBytes[0] & 
								OWNERTRUST_ULTIMATE_TRUST);
						// apply trust value
						applyTrust(sig, trust);
					}
				}
			}
		}
		
		// Step 3: for user objects, calculate/apply key legitimacy value
		for (Iterator ubi = bindings.iterator(); ubi.hasNext();) {
			UserObject uObj = (UserObject)ubi.next();
			
			int completes = 0, marginals = 0;
			// iterate through the signatures, calculating the key legitimacy
			for (Iterator sigs = uObj.getSignatureIterator(); sigs.hasNext();) {
				Signature sig = (Signature)sigs.next();
				
				// retrieve the signature trust value
				TrustPacket sigTrustPacket = sig.getTrust();
				byte[] trustBytes = sigTrustPacket.getTrust();
				int signatureTrust = trustBytes[0] & SIGTRUST_ULTIMATE_TRUST;
				
				// check for any kind of trust ...
				if (signatureTrust == SIGTRUST_USUALLY_TRUSTED) {
					++marginals;
					if (marginals >= marginalsNeeded) break;
				}
				else if (signatureTrust == SIGTRUST_ALWAYS_TRUSTED) {
					++completes;
					if (completes >= completesNeeded) break;
				}
				else if (signatureTrust == SIGTRUST_ULTIMATE_TRUST) {
					completes = completesNeeded;
					break;
				}
			}
			// apply the calculated trust value
			if (completes >= completesNeeded || marginals >= marginalsNeeded) {
				applyTrust(uObj, KEYLEGIT_COMPLETELY_TRUSTED);
			} else if (marginals > 0 || completes > 0) {
				float sum = ((float)completes)/((float)completesNeeded) + 
						((float)marginals)/((float)marginalsNeeded);
				if (sum >= 1f) {
					applyTrust(uObj, KEYLEGIT_COMPLETELY_TRUSTED);
				} else {
					applyTrust(uObj, KEYLEGIT_MARGINALLY_TRUSTED);
				}
			} else {
				applyTrust(uObj, KEYLEGIT_NOT_TRUSTED);
			}
		}
		
		// Calculate the trust values for the subkeys - this should be a copy 
		// of the signing key owner trust value
		for (Iterator ski = subkeys.iterator(); ski.hasNext();) {
			Subkey sk = (Subkey)ski.next();
			
			for (Iterator sigs = sk.getSignatureIterator(); sigs.hasNext();) {
				Signature sig = (Signature)sigs.next();
				
				if (sk.isRevoked() || !sk.isVerified()) {
					applyTrust(sig, OWNERTRUST_NOT_USUALLY_TRUSTED);
					// set the revoked flag bit
					// subkeyTrustPacket.getTrust()[0] |= OWNERTRUST_KEY_REVOKED;
				} else {
					// retrieve the signature trust value
					TrustPacket sigTrustPacket = sig.getTrust();
					byte[] trustBytes = sigTrustPacket.getTrust();
					
					// apply trust value using ultimate trust (111) as bitmask
					applyTrust(sk, trustBytes[0] & OWNERTRUST_ULTIMATE_TRUST);
				}
			}
		}
	}
	
	/**
	 * Method to swap insert a clean trust packet into a Trustable object. This
	 * will overwrite any existing trust packets.
	 * @param trustable The trustable object whose trust is to be cleared
	 * @throws AlgorithmException In case of problems
	 */
	public static void applyClearTrustPacket(Trustable trustable)
			throws AlgorithmException {
		byte[] trustBytes = new byte[1];
		TrustPacket trust = new TrustPacket(trustBytes);
		trustable.setTrust(trust);
	}
	
	/**
	 * Method to apply new, blank trust packets to a primary key. This is useful
	 * for new keys, whether created by the key manager or imported from an 
	 * external key source.
	 * @param primaryKey The key to have the trust applied
	 * @param cascade Whether or not to cascade the trust packets to user 
	 * bindings, subkeys, and certifying signatures.
	 */
	public static void applyClearTrust(PrimarySigningKey primaryKey, boolean cascade) {
		try {
			applyClearTrustPacket(primaryKey);
			
			// set the buckstop bit if this key is in the secret keyring
			if (primaryKey.isKeyPair()) {
				primaryKey.getTrust().getTrust()[0] |= OWNERTRUST_BUCKSTOP;
			}
			
			if (cascade) {
				// apply trust packets to any of primary key signatures
				Iterator sigit = primaryKey.getSignatureIterator();
				while (sigit.hasNext()) {
					applyClearTrustPacket((Signature)sigit.next());
				}
				
				// apply trust packets to any user IDs
				Iterator userit = primaryKey.getUserIDIterator(); 
				while (userit.hasNext()) {
					UserID uid = (UserID)userit.next();
					applyClearTrustPacket(uid);
					
					// apply trust packets to any certification signatures
					sigit = uid.getSignatureIterator();
					while (sigit.hasNext()) {
						applyClearTrustPacket((Signature)sigit.next());
					}
				}
				
				// apply trust packets to any user attributes
				userit = primaryKey.getUserAttributeIterator(); 
				while (userit.hasNext()) {
					UserAttribute uattr = (UserAttribute)userit.next();
					applyClearTrustPacket(uattr);
					
					// apply trust packets to any certification signatures
					sigit = uattr.getSignatureIterator();
					while (sigit.hasNext()) {
						applyClearTrustPacket((Signature)sigit.next());
					}
				}
				
				// apply trust packets to any subkeys
				Iterator ski = primaryKey.getSubkeyIterator();
				while (ski.hasNext()) {
					Subkey sk = (Subkey)ski.next();
					applyClearTrustPacket(sk);
					
					sigit = sk.getSignatureIterator();
					while (sigit.hasNext()) {
						applyClearTrustPacket((Signature)sigit.next());
					}
				}
			}
		} catch(AlgorithmException e) {e.printStackTrace();}
	}

	/** Method to retrieve the trust value.
	 * @param trustable The trustable object, containing a trust packet
	 * @return The trust value, as an integer
	 */
	public static int getTrustValue(Trustable trustable) {
		int trustValue = 0;
		TrustPacket trustPacket = trustable.getTrust();
		if (trustPacket != null) {
			byte[] trustBytes = trustPacket.getTrust();
			if (trustable instanceof UserObject) {  // UserObject: bits 0-1
				trustValue = trustBytes[0] & KEYLEGIT_COMPLETELY_TRUSTED;
			} else {  // PrimaryKey, Subkey, or Signature: bits 0-2
				trustValue = trustBytes[0] & OWNERTRUST_ULTIMATE_TRUST;
			}
		}
		return trustValue;
	}

	/** Method to retrieve the trust value in a readable form.
	 * @param trustable The trustable object, containing a trust packet
	 * @return The trust value for display, as a string
	 */
	public static String getDisplayableTrust(Trustable trustable) {
		int trustValue = getTrustValue(trustable);
		String display;
		if (trustable instanceof UserObject) {
			switch (trustValue) {
				case KEYLEGIT_UNDEFINED:
					display = "Undefined";
					break;
				case KEYLEGIT_NOT_TRUSTED:
					display = "Not Trusted";
					break;
				case KEYLEGIT_MARGINALLY_TRUSTED:
					display = "Marginally Trusted";
					break;
				case KEYLEGIT_COMPLETELY_TRUSTED:
					display = "Completely Trusted";
					break;
				default:
					display = "";
			}
		} else {  // must be PrimaryKey, Subkey, or Signature
			switch (trustValue) {
				case OWNERTRUST_UNDEFINED:
					display = "Undefined";
					break;
				case OWNERTRUST_UNKNOWN:
					display = "Unknown";
					break;
				case OWNERTRUST_NOT_USUALLY_TRUSTED:
					display = "Not Trusted";
					break;
				case OWNERTRUST_USUALLY_TRUSTED:
					display = "Usually Trusted";
					break;
				case OWNERTRUST_ALWAYS_TRUSTED:
					display = "Always Trusted";
					break;
				case OWNERTRUST_ULTIMATE_TRUST:
					display = "Ultimate Trust";
					break;
				default:
					display = "";
			}
		}
		return display;
	}

}
