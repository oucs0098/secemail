package openpgp.keystore.model;

import java.util.Iterator;

/** Interface to denote that an entity (e.g. primary key) can be bound to a user
 * @version $Id: UserBindable.java,v 1.3 2007-08-16 18:49:00 nigelb Exp $ 
 */
public interface UserBindable {
	
	/** This interface should be implemented by a class that is able to hold 
	 * UserID objects, and this method is the means by which those
	 * UserIDs are added.
	 * @param userID The UserID object to be added
	 */
	public void addUserID(UserID userID);
	
	/** This interface should be implemented by a class that is able to hold 
	 * UserAttribute objects, and this method is the means by which those
	 * UserAttributes are added.
	 * @param userAttribute The UserAttribute object to be added
	 */
	public void addUserAttribute(UserAttribute userAttribute);
	
	/** Method to return an iterator, to allow the sequential iteration over
	 * a collection of UserID objects.
	 * @return a UserID iterator
	 */
    public Iterator getUserIDIterator();
    
    /** Method to return an iterator, to allow the sequential iteration over
	 * a collection of UserAttribute objects.
	 * @return a UserAttribute iterator
	 */
    public Iterator getUserAttributeIterator();
}
