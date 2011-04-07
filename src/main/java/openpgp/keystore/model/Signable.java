package openpgp.keystore.model;

import java.util.Iterator;

/** Interface to denote that an entity can be signed
 * @version $Id: Signable.java,v 1.1 2007-08-07 13:15:57 nigelb Exp $ 
 */
public interface Signable {
	
	/** This interface should be implemented by a class that is able to hold 
	 * signature objects, and this method is the means by which those
	 * signatures are added.
	 * @param signature The signature object to be added
	 */
	public void addSignature(Signature signature);
	
	/** Method to return an iterator, to allow the sequential iteration over
	 * collections of signature objects.
	 * @return a signature iterator
	 */
    public Iterator getSignatureIterator();
    
}
