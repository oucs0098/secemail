package openpgp.keystore;

import java.util.Iterator;
import java.util.List;

import core.keyhandlers.identifiers.OpenPGPKeyIDKeyIdentifier;
import openpgp.keystore.exceptions.KeyMismatchException;
import openpgp.keystore.exceptions.RevocationException;
import openpgp.keystore.exceptions.VerificationException;
import openpgp.keystore.model.*;

/** Class to deal with validation-related tasks. So signature validation and
 * revocation validation for instance, should be coordinated by this class.
 * @version $Id: KeyStoreValidator.java,v 1.8 2007-08-25 14:10:31 nigelb Exp $
 */
public class KeyStoreValidator {
	
	/** Method to validate signatures attached to a user object.
	 * @param userObject The userObject containing signatures to be validated
	 * @param keyStore The key store containing the signing keys
	 */
	private static void validateUserObjectSignatures(UserObject userObject, 
			KeyStore keyStore) {
		for (Iterator si = userObject.getSignatureIterator(); si.hasNext();) {
			Signature sig = (Signature)si.next();
			// If signature material is flawed (eg. PGP X509), skip sig
			if (sig.getRawSigningKeyID() == null) continue;
			// otherwise try and validate it
			try {
				OpenPGPKeyIDKeyIdentifier id = 
						new OpenPGPKeyIDKeyIdentifier(
								sig.getRawSigningKeyID());
				List keyList = keyStore.findPrimaryKeys(id);
				if (keyList != null && keyList.size() == 1) {
					PrimarySigningKey key = (PrimarySigningKey)keyList.get(0);
					if (!sig.isVerified()) {
						debug.Debug.println(1, "Verify certification " +
								"from key ID " + key.getShortKeyID() +
								" (" + key.getPrimaryEmailAddress() + ")");
						boolean result = sig.verifyCertificationSignature(key);
						debug.Debug.println(1, "Valid: " + result);
					}
					if (sig.isRevoked() && sig.isVerified() &&
							!sig.getRevocationSignature().isVerified()) {
						debug.Debug.println(1, "Verify revocation " +
								"from key ID " + key.getShortKeyID() +
								" (" + key.getPrimaryEmailAddress() + ")");
						boolean result = sig.verifyRevocationSignature(key);
						debug.Debug.println(1, "Valid: " + result);
					}
				} else {
					if (keyList == null)
						debug.Debug.println(1, "Error: Signing key not found");
					else
						debug.Debug.println(1, "Error: " + keyList.size() + 
								" key matches found");
				}
			} catch(Exception e) {
				e.printStackTrace();
			}
		}
	}

	/** Method to validate all signatures that are not already validated
	 * @param keyStore The key store to validate
	 */
	public static void validateSignatures(KeyStore keyStore) {
		// Validate the certification & certification revocation signatures
		for (Iterator keyit = keyStore.getAllKeysIterator(); keyit.hasNext();) {
			PrimarySigningKey psk = (PrimarySigningKey)keyit.next();
			
			// validate key revocation signatures
			if (psk.isRevoked() && !psk.getRevocationSignature().isVerified()) {
				try {
					debug.Debug.println(1, "Verify direct key revocation " +
							"of key ID " + psk.getShortKeyID() + " (" + 
							psk.getPrimaryEmailAddress() + ")");
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
			
			// validate user id certification/revocation signatures
			for (Iterator uii = psk.getUserIDIterator(); uii.hasNext();) {
				UserID uid = (UserID)uii.next();
				validateUserObjectSignatures(uid, keyStore);
			}
			
			// validate user attribute certification/revocation signatures
			for (Iterator uai = psk.getUserAttributeIterator(); uai.hasNext();) {
				UserAttribute uattr = (UserAttribute)uai.next();
				validateUserObjectSignatures(uattr, keyStore);
			}
			
			// validate subkey signature revocations
			for (Iterator ski = psk.getSubkeyIterator(); ski.hasNext();) {
				Subkey sk = (Subkey)ski.next();
				if (sk.isRevoked() && !sk.getRevocationSignature().isVerified()) {
					try {
						debug.Debug.println(1, "Verify subkey revocation " +
								"from key ID " + psk.getShortKeyID() +
								" (" + psk.getPrimaryEmailAddress() + ")");
						boolean isValid = sk.verifyRevocationSignature(psk);
						debug.Debug.println(1, "Valid: " + isValid);
					} catch(KeyMismatchException e) {
						e.printStackTrace();
					} catch(RevocationException e) {
						e.printStackTrace();
					}
				}
				
				// validate subkey binding signature
				for (Iterator sigs = sk.getSignatureIterator(); sigs.hasNext();) {
					Signature sig = (Signature)sigs.next();
					if (!sig.isVerified()) {
						try {
							debug.Debug.println(1, "Verify subkey binding " +
									"from key ID " + psk.getShortKeyID() +
									" (" + psk.getPrimaryEmailAddress() + ")");
							boolean isValid = sk.verifyBindingSignature();
							debug.Debug.println(1, "Valid: " + isValid);
						} catch(KeyMismatchException e) {
							e.printStackTrace();
						} catch(VerificationException e) {
							e.printStackTrace();
						}
					}
				}
				
			}
		}
	}
}
