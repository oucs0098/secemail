package openpgp.keystore.model;

import core.algorithmhandlers.openpgp.packets.UserAttributePacket;

/** The User Attribute class, which represents the binding of a user attribute
 * to a primary signing key, in the same way that the user ID does. The
 * only currently defined user attribute is the photo.
 * @version $Id: UserAttribute.java,v 1.5 2007-08-27 20:52:36 nigelb Exp $
 */
public class UserAttribute extends UserObject {
	
	/** The main constructor
     * @param userIDPkt the user UD packet
     * @param primarySigningKey The key this user ID is bound to
     */
    public UserAttribute(UserAttributePacket userAttributePkt, 
    		PrimarySigningKey primarySigningKey) {
    	userPacket = userAttributePkt;
        this.signingKey = primarySigningKey;
    }

    /** @see openpgp.keystore.model.KeyStoreNode#getIconType() */
	public int getIconType() {
		if (this.isSelfSignatureRevoked())
			return DISABLED_USER_ATTRIBUTE_NODE;
		else
			return USER_ATTRIBUTE_NODE;
	}
	
	/** @see java.lang.Object#toString() */
	public String toString() {
		return "User Photograph";  // photo is the only user attribute defined
	}

}
