package openpgp.keystore.model;

import java.util.Date;

/** Interface denoting that an implementing class is capable of expiring, that
 * is, it can carry an expiration date.
 * @version $Id: Expirable.java,v 1.1 2007-08-07 13:15:57 nigelb Exp $
 */
public interface Expirable {

	/** @return the date and time that this entity expires, or null if the 
	 * entity does not expire.
	 */
	public Date getExpirationDate();
	
	/** @return Whether or not this entity's expiration date has passed
	 * (always returns false if the entity does not expire).
	 */
	public boolean hasExpired();
	
}
