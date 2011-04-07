package openpgp.keystore.util;

import java.util.Enumeration;
import java.util.Iterator;

/** Backwards-compatibility utility to expose the Enumeration methods for 
 * an iterator - the immediate need is to get round the restrictions of 
 * the TreeNode interface methods. This wrapper can be used wherever an 
 * Enumeration is required, and when only an Iterator is available. The
 * two classes are almost identical, differing only in the method name
 * lengths, and the fact that the Iterator interface defines an optional
 * 'remove()' method.
 * @version $Id: IteratorWrapper.java,v 1.1 2007-08-07 13:15:57 nigelb Exp $
 */
public class IteratorWrapper implements Enumeration {
	
	/** The wrapped iterator */
	Iterator iterator;
	
	/** Constructor, requires an iterator to wrap */ 
	public IteratorWrapper(Iterator iterator) {
		this.iterator = iterator;
	}
	
	/** @see java.util.Enumeration#hasMoreElements() */
	public boolean hasMoreElements() {
		return iterator.hasNext();
	}
	
	/** @see java.util.Enumeration#nextElement() */
	public Object nextElement() {
		return iterator.next();
	}
	
}
