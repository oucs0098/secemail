package openpgp.keystore.model;

import java.util.Iterator;

/** Interface to denote that an entity (e.g. key store) can hold keys
 * @version $Id: KeyHolder.java,v 1.2 2007-08-17 17:24:22 nigelb Exp $ 
 */
public interface KeyHolder {

	/** This interface should be implemented by a class that is able to hold 
	 * PrimarySigningKey objects, and this method is the means by which those
	 * PrimarySigningKeys are added.
	 * @param key The PrimarySigningKey object to be added
	 */
	public void addKey(PrimarySigningKey key);
	
	/** Method to return an iterator, to allow the sequential iteration over
	 * collections of PrimarySigningKey objects.
	 * @return a PrimarySigningKey iterator
	 */
    public Iterator getKeyIterator();
    
}
