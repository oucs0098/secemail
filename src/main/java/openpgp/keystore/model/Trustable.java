package openpgp.keystore.model;

import core.algorithmhandlers.openpgp.packets.*;

/** Interface to denote that an entity can have a level of trust assigned to 
 * it 
 * @version $Id: Trustable.java,v 1.2 2007-08-17 17:24:22 nigelb Exp $
 */
public interface Trustable {
	
	/** Set the trust level for this entity
	 * @param trustPkt The TrustPacket object encapsulating the level of trust
	 */
	public void setTrust(TrustPacket trustPkt);
	
	/** Get the trust level for this entity
	 * @return The TrustPacket object encapsulating the level of trust
	 */
    public TrustPacket getTrust();
}
