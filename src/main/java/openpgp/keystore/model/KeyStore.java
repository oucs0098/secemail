package openpgp.keystore.model;

import java.util.Comparator;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.ArrayList;
import java.util.Vector;
import java.util.Collection;
import java.util.HashMap;
import java.util.TreeSet;
import java.util.Set;
import java.util.Observable;
import javax.swing.tree.MutableTreeNode;
import javax.swing.tree.TreeNode;

import openpgp.keystore.util.IteratorWrapper;
import openpgp.keystore.util.StringHelper;
import core.keyhandlers.KeyIdentifier;
import core.keyhandlers.identifiers.*;
import core.exceptions.KeyHandlerException;

/** <p>Wrapper class, representing a group of certificates making up a 
 * keyring or pair of keyrings.</p>
 * <p>This key store amalgamates keys from the filesystem-based public and 
 * private keyrings, storing the key references in different collections for
 * different purposes.</p>
 * @version $Id: KeyStore.java,v 1.4 2007-08-25 14:09:52 nigelb Exp $
 */
public class KeyStore extends Observable implements KeyStoreNode, KeyHolder {

	/** All certificates in a form searchable by long key ID */
	private HashMap longKeyIDMap = new HashMap();
	
	/** All certificates in a form searchable by short key ID */
	private HashMap shortKeyIDMap = new HashMap();
	
	/** All certificates in a form searchable by user ID - NOTE: user ID keys 
	 * are set to lower case when used as keys (this enables case-insensitive
	 * searches)
	 */
	private HashMap userIDKeyMap = new HashMap();
	
	/** All certificates in this key store */
	private TreeSet allKeys = new TreeSet(new KeyStoreChildComparator());
	
	/** All private certificates in this key store */
	private TreeSet privateKeys = new TreeSet(new KeyStoreChildComparator());
	
	/** Whether to show only secret keyring keypairs (or all keys) */
	private boolean privateKeysOnly = false;
	
	/** Method to clear the keyring of all keys */
	public void clear() {
		allKeys.clear();
		privateKeys.clear();
		userIDKeyMap.clear();
		shortKeyIDMap.clear();
		longKeyIDMap.clear();
		setChanged();
		notifyObservers();
	}
	
	/** Method to add a key to the key store
	 * @param key The key to add to the key store
	 */
	public void addKey(PrimarySigningKey key) {
		key.setParent(this);
		allKeys.add(key);
		if (key.isKeyPair()) privateKeys.add(key);
		addToSearchMaps(key);
		setChanged();
		notifyObservers();
	}
	
	/** Method to mark the keystore as changed, and notify observers, without
	 * adding anything or taking anything away.
	 */
	public void touch() {
		setChanged();
		notifyObservers();
	}
	
	/** Method to add a key to any searchable key maps */
	private void addToSearchMaps(PrimarySigningKey key) {
		// add to long key ID key map
		List keyList = (List)longKeyIDMap.get(key.getLongKeyID());
		if (keyList != null) {
			keyList.add(key);
		} else {
			keyList = new ArrayList();
			keyList.add(key);
			longKeyIDMap.put(key.getLongKeyID(), keyList);
		}
		// add to short key ID key map
		keyList = (List)shortKeyIDMap.get(key.getShortKeyID());
		if (keyList != null) {
			keyList.add(key);
		} else {
			keyList = new ArrayList();
			keyList.add(key);
			shortKeyIDMap.put(key.getShortKeyID(), keyList);
		}
		// add to user ID key map
		for (Iterator it = key.getUserIDIterator(); it.hasNext();) {
			UserID uid = (UserID)it.next();
			keyList = (List)userIDKeyMap.get(uid.getUserID().toLowerCase());
			if (keyList != null) {
				keyList.add(key);
			} else {
				keyList = new ArrayList();
				keyList.add(key);
				userIDKeyMap.put(uid.getUserID().toLowerCase(), keyList);
			}
		}
	}
	
	/** Method to remove a key from any searchable key maps */
	private void removeFromSearchMaps(PrimarySigningKey key) {
		// remove from long key ID map
		List keyList = (List)longKeyIDMap.get(key.getLongKeyID());
		if (keyList != null) keyList.remove(key);
		// remove from short key ID map
		keyList = (List)shortKeyIDMap.get(key.getShortKeyID());
		if (keyList != null) keyList.remove(key);
		// remove from user ID key map
		for (Iterator it = key.getUserIDIterator(); it.hasNext();) {
			UserID uid = (UserID)it.next();
			keyList = (List)userIDKeyMap.get(uid.getUserID().toLowerCase());
			if (keyList != null) keyList.remove(key);
		}
	}
	
	/** Method to get an iterator over all the key store keys
	 * @return an iterator over the key store keys
	 */
	public Iterator getAllKeysIterator() {
		return allKeys.iterator();
	}
	
	/** Method to get a count of all the key store keys
	 * @return the total number of keys in the 'all keys' set
	 */
	public int getAllKeysCount() {
		return allKeys.size();
	}
	
	/** Method to get an iterator over the currently active key store keys
	 * @return an iterator over the keyring keys
	 */
	public Iterator getKeyIterator() {
		return getActiveKeys().iterator();
	}

	/** Method to return keys that are currently viewed (all or private only) */
	private Set getActiveKeys() {
		if (privateKeysOnly)
			return privateKeys;
		else
			return allKeys;
	}
	
	/** Method to return the set of keys that is not currently viewed */
	private Set getInactiveKeys() {
		if (privateKeysOnly)
			return allKeys;
		else
			return privateKeys;
	}
	
	/** @see javax.swing.tree.TreeNode#children() */
	public Enumeration children() {
		return new IteratorWrapper(getActiveKeys().iterator());
	}

	/** @see javax.swing.tree.TreeNode#getAllowsChildren() */
	public boolean getAllowsChildren() {
		return true;
	}

	/** @see javax.swing.tree.TreeNode#getChildAt(int) */
	public TreeNode getChildAt(int childIndex) {
		return (TreeNode)getActiveKeys().toArray()[childIndex];
	}

	/** @see javax.swing.tree.TreeNode#getChildCount() */
	public int getChildCount() {
		return getActiveKeys().size();
	}

	/** @see javax.swing.tree.TreeNode#getIndex(javax.swing.tree.TreeNode) */
	public int getIndex(TreeNode node) {
		return new Vector(getActiveKeys()).indexOf(node);
	}

	/** @see javax.swing.tree.TreeNode#getParent() */
	public TreeNode getParent() {
		return null;
	}

	/** @see javax.swing.tree.TreeNode#isLeaf() */
	public boolean isLeaf() {
		return getActiveKeys().isEmpty();
	}

	/** @return whether to only show secret keyring keypairs */
	public boolean isPrivateKeysOnly() {
		return privateKeysOnly;
	}

	/** @param privateKeysOnly whether to only show secret keyring keypairs */
	public void setPrivateKeysOnly(boolean privateKeysOnly) {
		this.privateKeysOnly = privateKeysOnly;
	}

	/* @see java.lang.Object#toString() */
	public String toString() {
		String description;
		if (isPrivateKeysOnly()) {
			if (privateKeys.isEmpty()) {
				description = "No Private Keys Available";
			} else {
				description = "All Private Keys"; 
			}
		} else {
			if (allKeys.isEmpty()) {
				description = "No Keys Available";
			} else {
				description = "All Keys"; 
			}
		}
		return description;
	}

	/** @see openpgp.keystore.model.KeyStoreNode#getIconType() */
	public int getIconType() {
		return KEYRING_NODE;
	}

	/** Adds child to the receiver at index. */
	public void insert(MutableTreeNode child, int index) {
		Vector active = new Vector(getActiveKeys());
		Vector inactive = new Vector(getInactiveKeys());
		active.insertElementAt(child, index);
		if (index >= inactive.size()) {  // inactive: index may be out of bounds
			inactive.add(child);
		} else {
			inactive.insertElementAt(child, index);
		}
		// add to the search maps, position is unimportant
		addToSearchMaps((PrimarySigningKey)child);
		setChanged();
		notifyObservers();
	}

	/** Removes the child at index from the receiver. */
	public void remove(int index) {
		PrimarySigningKey pk = (PrimarySigningKey)getActiveKeys().toArray()[index];
		allKeys.remove(pk);
		privateKeys.remove(pk);
		removeFromSearchMaps(pk);  // remove from key maps
		setChanged();
		notifyObservers();
	}

	/** Removes node from the receiver. */
	public void remove(MutableTreeNode node) {
		allKeys.remove(node);
		privateKeys.remove(node);
		removeFromSearchMaps((PrimarySigningKey)node);  // remove from key maps
		setChanged();
		notifyObservers();
	}

	/** Removes the receiver from its parent. */
	public void removeFromParent() {
		throw new UnsupportedOperationException();
	}

	/** Sets the parent of the receiver to newParent. */
	public void setParent(MutableTreeNode newParent) {
		throw new UnsupportedOperationException();
	}

	/** Resets the user object of the receiver to object. */
	public void setUserObject(Object object) {
		throw new UnsupportedOperationException();
	}
	
	/** Method to find any primary keys matching a given key ID - this key ID
	 * can be a long key ID or a short key ID, the method will attempt to
	 * match the short key ID if the long key ID match fails.
	 * @param keyID The key ID to find matching primary keys with
	 * @return a list of matching keys, or null if none found
	 */
	public List findPrimaryKeys(KeyIdentifier id) throws KeyHandlerException {
		List results = null;
		if (id instanceof OpenPGPKeyIDKeyIdentifier) {
			// convert to a hex string first
			String hexID = StringHelper.toHexString(id.getDefaultID());
			if (hexID.startsWith("00000000")) {  // use short key ID
				hexID = "0x" + hexID.substring(8);
				results = (List)shortKeyIDMap.get(hexID);
			} else {  // use long key ID
				results = (List)longKeyIDMap.get(hexID);
			}
		} else if (id instanceof OpenPGPStandardKeyIdentifier) {
			results = (List)userIDKeyMap.get(
					new String(id.getDefaultID()).toLowerCase());
		} else if (id instanceof OpenPGPFreeTextKeyIdentifier) {
			String searchString = new String(id.getDefaultID());
			List resultList = new ArrayList();
			// try a search in the long key IDs first ...
			Set longKeyIDSet = longKeyIDMap.keySet();
			for (Iterator it = longKeyIDSet.iterator(); it.hasNext();) {
				String longKeyID = (String)it.next();
				if (longKeyID.indexOf(searchString) > -1) {
					// add the list to the result set
					resultList.add(longKeyIDMap.get(longKeyID));
				}
			}
			// then a search in the short key IDs ...
			Set shortKeyIDSet = shortKeyIDMap.keySet();
			for (Iterator it = shortKeyIDSet.iterator(); it.hasNext();) {
				String shortKeyID = (String)it.next();
				if (shortKeyID.indexOf(searchString) > -1) {
					// add the list to the result set
					resultList.add(shortKeyIDMap.get(shortKeyID));
				}
			}
			// finally a search in the user IDs ...
			Set userIDSet = userIDKeyMap.keySet();
			for (Iterator it = userIDSet.iterator(); it.hasNext();) {
				String userID = (String)it.next();
				if (userID.indexOf(searchString.toLowerCase()) > -1) {
					// add the list to the result set
					resultList.add(userIDKeyMap.get(userID));
				}
			}
			// and collate the results ...
			if (!resultList.isEmpty()) {
				results = new ArrayList();
				for (int i = 0; i < resultList.size(); ++i) {
					List keyList = (List)resultList.get(i);
					for (int j = 0; j < keyList.size(); ++j) {
						results.add(keyList.get(j));
					}
				}
			}
		}
		return results;
	}
	
	/** Method to find all user binding (certification) signatures made by a 
	 * key with a given long key ID. To do this the object needs to search 
	 * through the key store. There should be a more efficient way to do this.
	 * @param longKeyID The key ID to find matching signatures with
	 * @return a list of matching keys, or null if none found
	 */
	public List getCertificationSignatures(String longKeyID) {
		List signatures = new ArrayList();
		// for each primary key
		for (Iterator aki = getAllKeysIterator(); aki.hasNext();) {
			PrimarySigningKey pk = (PrimarySigningKey)aki.next();
			// for each user binding
			for (Iterator uit = pk.getUserIDIterator(); uit.hasNext();) {
				UserID uid = (UserID)uit.next();
				// for each signature
				for (Iterator si = uid.getSignatureIterator(); si.hasNext();) {
					Signature s = (Signature)si.next();
					// if there's a matching signature, add it
					if (s.getSigningKeyLongID().equals(longKeyID)) {
						signatures.add(s);
					}
				}
			}
		}
		return signatures;
	}
	
	/** Method to get all private keys capable of certifying other keys
	 * @return a collection of keys capable of certifying other keys 
	 */
	public Collection getCertificationKeys() {
		Vector keys = new Vector();
		for (Iterator it = privateKeys.iterator(); it.hasNext();) {
			PrimarySigningKey key = (PrimarySigningKey)it.next();
			if (key.canCertifyKeys()) keys.add(key);
		}
		return keys;
	}
	
	/** Inner class to produce an ordering in the child elements. */
	private class KeyStoreChildComparator implements Comparator {
		// constants
		private final static int ORDER_BY_USERID = 0, ORDER_BY_KEYID = 1;
		// instance variable, holds the order code
		private int ordering;  // defaults to 0
		
		/** Constructor, uses the default ordering */
		KeyStoreChildComparator() {super();}
		
		/** Constructor, sets the code for the element to order by */
		KeyStoreChildComparator(int orderCode) {
			this();
			switch(orderCode) {
				case ORDER_BY_USERID:
				case ORDER_BY_KEYID:
					ordering = orderCode;
					break;
				default: // unknown code - keeps the default
			}
		}

		/** Method to compare the key store children (primary signing keys), to
		 * produce a natural ordering. By default, the ordering is by user id.
		 * @see java.util.Comparator#compare(java.lang.Object, java.lang.Object)
		 */
		public int compare(Object obj1, Object obj2) {
			int result = 0;
			if (obj1 instanceof PrimarySigningKey && obj2 instanceof PrimarySigningKey) {
				PrimarySigningKey pk1 = (PrimarySigningKey)obj1;
				PrimarySigningKey pk2 = (PrimarySigningKey)obj2;
				switch(ordering) {
					case ORDER_BY_USERID:
						result = pk1.getPrimaryEmailAddress().toLowerCase().compareTo(
								pk2.getPrimaryEmailAddress().toLowerCase());
						break;
					case ORDER_BY_KEYID:
						result = pk1.getLongKeyID().compareTo(
								pk2.getLongKeyID());
						break;
					default: // unknown code - no ordering applied
				}
			}
			return result;
		}
	}
	
	

}
