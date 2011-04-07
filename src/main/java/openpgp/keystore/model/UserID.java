package openpgp.keystore.model;

import core.algorithmhandlers.openpgp.packets.*;
import core.keyhandlers.identifiers.OpenPGPStandardKeyIdentifier;
import core.exceptions.*;

/** The UserID class, which represents the binding of a user to a primary
 * signing key.
 * @version $Id: UserID.java,v 1.5 2007-08-27 20:54:59 nigelb Exp $
 */
public class UserID extends UserObject {

	// The standard key identifier, using the user ID
	private OpenPGPStandardKeyIdentifier standardKeyIdentifier;
	// The user ID in string form
	private String userID;
    
    /** The main constructor
     * @param userIDPacket the user UD packet
     * @param primarySigningKey The key this user ID is bound to
     */
    public UserID(UserIDPacket userIDPacket, PrimarySigningKey primarySigningKey) {
    	this.userPacket = userIDPacket;
    	userID = new String(userIDPacket.getID());
    	try {
    		standardKeyIdentifier = new OpenPGPStandardKeyIdentifier(userID);
    	} catch(KeyHandlerException e) {
    		// User ID format is unrecognisable (could not parse email address)
    		standardKeyIdentifier = new OpenPGPStandardKeyIdentifier(
    				userID.getBytes(), "<>".getBytes());
	    }
        this.signingKey = primarySigningKey;
    }
    
	/** Accessor method
	 * @return the user ID in string form
	 */
	public String getUserID() {
		return userID;
	}
	
	/** @see java.lang.Object#toString() */
	public String toString() {
		return getUserID();
	}

	/** @see java.lang.Object#equals(java.lang.Object) */
	public boolean equals(Object obj) {
		boolean result = false;
		if (this == obj) result = true;
		if (obj instanceof UserID) {
			result = getUserID().equals(((UserID)obj).getUserID());
		}
		return result;
	}

	/** @see openpgp.keystore.model.KeyStoreNode#getIconType() */
	public int getIconType() {
		if (this.isSelfSignatureRevoked())
			return DISABLED_USER_ID_NODE;
		else
			return USER_ID_NODE;
	}
	
	/** @return whether this binding is the signing key's only user binding */
	public boolean isSoleUserID() {
		return (signingKey.getUserIDCount() == 1);
	}

	/** @return whether this user ID is the primary user ID */
	public boolean isPrimaryUserID() {
		boolean isPrimary = false;
		Signature s = getSelfSignature();
		if (s != null) {
			isPrimary = s.isPrimaryUserID();
		}
		if (!isPrimary && isSoleUserID()) {
			isPrimary = true;
		}
		return isPrimary;
	}

	/** @return the key identifier */
	public OpenPGPStandardKeyIdentifier getStandardKeyIdentifier() {
		return standardKeyIdentifier;
	}
	
}
