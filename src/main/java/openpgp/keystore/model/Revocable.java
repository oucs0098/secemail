package openpgp.keystore.model;

import openpgp.keystore.exceptions.*;
import core.algorithmhandlers.PassPhrase;

/** Interface defining methods for revocable entities (word meaning the 
 * opposite of irrevocable)
 * @version $Id: Revocable.java,v 1.1 2007-08-07 13:15:57 nigelb Exp $
 */
public interface Revocable {

	/** Accessor method, gets a revocation signature from the revoked object.
	 * Examples of revocation signatures that could be returned from this 
	 * method are 0x20 (primary key revocation signature), 0x28 (subkey
	 * revocation signature), and 0x30 (certification revocation signature).
	 * @return The revocation signature doing the revoking
	 */
	public Signature getRevocationSignature();
	
	/** Method to set an object as revoked. Once an object has been revoked it 
	 * cannot be unrevoked. Examples of revocation signatures that could be
	 * passed into this method are 0x20 (primary key revocation signature), 
	 * 0x28 (subkey revocation signature), and 0x30 (certification revocation
	 * signature).
	 * @param The revocation signature doing the revoking
	 */
	public void setRevocationSignature(Signature signature);
	
	/** Method to verify a revocation signature. This method requires the 
	 * public key corresponding to the private key that was used to create this
	 * signature, for verification. 
	 * @param key The primary signing key
	 * @return true if the revocation signature is valid, false if not valid
	 */
	public boolean verifyRevocationSignature(PrimarySigningKey key)
			throws RevocationException, KeyMismatchException;
	
	/** @return whether the implementing object is (or is not) revoked */
	public boolean isRevoked();
	
	/** Method to revoke this object. The key doing the revoking that is passed
	 * into this method should be a top-level primary signing key, available on
	 * the same keyring that this revocable object is on.
	 * @param key The top-level signing key doing the revoking.
	 * @param passphrase The passphrase of the revoking secret key
	 * @param reason The reason for revocation. The constants are in the
	 * ReasonForRevocation subpacket
	 * @throws RevocationException in case the object is already revoked
	 * @throws KeyMismatchException if the revoking primary key is not 
	 * appropriate to be used for revoking this object.
	 * @see core.algorithmhandlers.openpgp.packets.v4signature.ReasonForRevocationSubpacket
	 */
	public void revoke(PrimarySigningKey key, PassPhrase passPhrase, int reason)
			throws RevocationException, KeyMismatchException;
	
}
