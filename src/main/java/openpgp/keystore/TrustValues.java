package openpgp.keystore;

/** <p><pre>Interface grouping the trust values - most of the values are
 * directly from Phil Zimmermann's 1994 document 
 * <pre>'File Formats Used by PGP 2.6'.</pre>This was done to preserve some
 * compatibility between the keyrings used by the key manager and those used
 * by PGP, because the PGP trust packets have not changed much since then.</p>
 * <p>The trust values not based on that document are the mask values, the
 * revocation and disabled bits, and any subkey or user attribute notes 
 * (subkeys were introduced since that version - note that the subkey values
 * are the same as the owner trust - and signature trust - values; user 
 * attributes are new additions too and use the same values as user objects, 
 * key legitimacy).</p>
 * @see http://www.cl.cam.ac.uk/PGP/pgformat.ps.gz
 * @version $Id: TrustValues.java,v 1.2 2007-08-24 16:02:53 nigelb Exp $
 */
public interface TrustValues {

	//------------------------------------------------------------------------
	// OWNERTRUST values for a key owner.
	//------------------------------------------------------------------------
	
	/** Undefined, or uninitialised trust */
	public final static byte OWNERTRUST_UNDEFINED = (byte)0x00;
	
	/** Unknown, we don't know the owner of this key */
	public final static byte OWNERTRUST_UNKNOWN = (byte)0x01;
	
	/** We don't usually trust this key owner to sign other keys */
	public final static byte OWNERTRUST_NOT_USUALLY_TRUSTED = (byte)0x02;
	
	/** Reserved value */
	public final static byte OWNERTRUST_RESERVED_3 = (byte)0x03;
	
	/** Reserved value */
	public final static byte OWNERTRUST_RESERVED_4 = (byte)0x04;
	
	/** We usually do trust this key owner to sign other keys */
	public final static byte OWNERTRUST_USUALLY_TRUSTED = (byte)0x05;
	
	/** We always trust this key owner to sign other keys */
	public final static byte OWNERTRUST_ALWAYS_TRUSTED = (byte)0x06;
	
	/** This key is also present in the secret keyring */
	public final static byte OWNERTRUST_ULTIMATE_TRUST = (byte)0x07;
	
	/** Means that this key is revoked, and should not be used */
	public final static byte OWNERTRUST_KEY_REVOKED = (byte)0x10;
	
	/** Means that this key is disabled, and should not be used */
	public final static byte OWNERTRUST_KEY_DISABLED = (byte)0x20;
	
	/** Means that this key is expired, and should not be used */
	public final static byte OWNERTRUST_KEY_EXPIRED = (byte)0x40;
	
	/** Means this key also appears in the secret key ring. Signifies the
	 * ultimately-trusted "keyring owner". If this bit is set, then all the 
	 * KEYLEGIT fields are set to maximum for all the user IDs for this key,
	 * and OWNERTRUST is also set to maximum trust 
	 */
	public final static byte OWNERTRUST_BUCKSTOP = (byte)0x80;
	
	//------------------------------------------------------------------------
	// OWNERTRUST bit mask value.
	//------------------------------------------------------------------------
	
	/** OWNERTRUST bitmask, used to clear the trust values */
	public final static byte OWNERTRUST_MASK_ALLTRUST = (byte)0xF8;
	
	//------------------------------------------------------------------------
	// SUBKEYTRUST values for a subkey's trust byte are identical to those for
	// OWNERTRUST, so use them for subkeys too.
	//------------------------------------------------------------------------
	
	//------------------------------------------------------------------------
	// KEYLEGIT validity bits for the user objects.
	//------------------------------------------------------------------------
	
	/** Unknown, undefined, or uninitialised trust */
	public final static byte KEYLEGIT_UNDEFINED = (byte)0x00;
	
	/** We do not trust this key's ownership */
	public final static byte KEYLEGIT_NOT_TRUSTED = (byte)0x01;
	
	/** We have marginal confidence of this key's ownership */
	public final static byte KEYLEGIT_MARGINALLY_TRUSTED = (byte)0x02;
	
	/** We completely trust this key's ownership */
	public final static byte KEYLEGIT_COMPLETELY_TRUSTED = (byte)0x03;
	
	/** If the user wants to use a not fully validated key for encryption,
	 * the user is asked if he/she really wants to use this key. If the
	 * answer is 'yes' the WARNONLY bit is set, and the next time he/she 
	 * uses this key, only a warning will be shown. This bit gets cleared
	 * during the PGP maintenance pass.
	 */
	public final static byte KEYLEGIT_WARNONLY = (byte)0x80;
	
	//------------------------------------------------------------------------
	// KEYLEGIT bit mask values.
	//------------------------------------------------------------------------
	
	/** KEYLEGIT bitmask, used to clear the trust values */
	public final static byte KEYLEGIT_MASK_ALLTRUST = (byte)0xFC;
	
	//------------------------------------------------------------------------
	// SIGTRUST bits for this signature. The value is copied directly from the
	// OWNERTRUST bits of the signer or from a trust signature.
	//------------------------------------------------------------------------
	
	/** Undefined, or uninitialised trust */
	public final static byte SIGTRUST_UNDEFINED = (byte)0x00;
	
	/** Unknown */
	public final static byte SIGTRUST_UNKNOWN = (byte)0x01;
	
	/** We don't trust this signature */
	public final static byte SIGTRUST_NOT_USUALLY_TRUSTED = (byte)0x02;
	
	/** Reserved value */
	public final static byte SIGTRUST_RESERVED_3 = (byte)0x03;
	
	/** Reserved value */
	public final static byte SIGTRUST_RESERVED_4 = (byte)0x04;
	
	/** We usually do trust this signature */
	public final static byte SIGTRUST_USUALLY_TRUSTED = (byte)0x05;
	
	/** We always trust this signature */
	public final static byte SIGTRUST_ALWAYS_TRUSTED = (byte)0x06;
	
	/** Ultimately trusted signature (from the owner of the keyring) */
	public final static byte SIGTRUST_ULTIMATE_TRUST = (byte)0x07;
	
	/** Means that this key is revoked, and should not be used */
	public final static byte SIGTRUST_SIG_REVOKED = (byte)0x10;
	
	/** This means that the key checking pass has tested this signature and 
	 * found it good. If this bit is not set, the maintenance pass considers
	 * this signature untrustworthy.
	 */
	public final static byte SIGTRUST_CHECKED = (byte)0x40;
	
	/** Means that this signature leads up a contiguous trusted certification
	 * path all the way back to the ultimately-trusted keyring owner, where the
	 * buck stops. This bit is derived from other trust packets. It is currently
	 * not used in PGP.
	 */
	public final static byte SIGTRUST_CONTIG = (byte)0x80;
	
	//------------------------------------------------------------------------
	// SIGTRUST bit mask values.
	//------------------------------------------------------------------------
	
	/** SIGTRUST bitmask, used to clear the trust values */
	public final static byte SIGTRUST_MASK_ALLTRUST = (byte)0xF8;
	
	
	
}
