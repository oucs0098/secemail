package openpgp.keystore.model;

import javax.swing.tree.MutableTreeNode;

/** Interface to specify node behaviour for nodes that can occur in a 
 * key store JTree.
 * @version $Id: KeyStoreNode.java,v 1.4 2007-08-25 14:09:05 nigelb Exp $
 */
public interface KeyStoreNode extends MutableTreeNode {
	
	// Icon types, used to identify node types for iconification.
	// El Gamal doesn't crop up because only signing keys appear in the tree
	/** Keyring Node (root node) */
	public static final int KEYRING_NODE = 1;
	/** RSA key pair (public and private keys) node */
	public static final int RSA_KEY_PAIR_NODE = 2;
	/** RSA disabled key pair (public and private keys) node */
	public static final int RSA_DISABLED_KEY_PAIR_NODE = 3;
	/** RSA public key node */
	public static final int RSA_PUBLIC_KEY_NODE = 4;
	/** RSA disabled public key node */
	public static final int RSA_DISABLED_PUBLIC_KEY_NODE = 5;
	/** DSA key pair (public and private keys) node */
	public static final int DSA_KEY_PAIR_NODE = 6;
	/** DSA disabled key pair (public and private keys) node */
	public static final int DSA_DISABLED_KEY_PAIR_NODE = 7;
	/** DSA public key node */
	public static final int DSA_PUBLIC_KEY_NODE = 8;
	/** DSA disabled public key node */
	public static final int DSA_DISABLED_PUBLIC_KEY_NODE = 9;
	/** El Gamal key pair (public and private keys) node */
	public static final int ELGAMAL_KEY_PAIR_NODE = 10;
	/** El Gamal disabled key pair (public and private keys) node */
	public static final int ELGAMAL_DISABLED_KEY_PAIR_NODE = 11;
	/** El Gamal public key node */
	public static final int ELGAMAL_PUBLIC_KEY_NODE = 12;
	/** El Gamal disabled public key node */
	public static final int ELGAMAL_DISABLED_PUBLIC_KEY_NODE = 13;
	/** User ID node */
	public static final int USER_ID_NODE = 14;
	/** Disabled user ID node */
	public static final int DISABLED_USER_ID_NODE = 15;
	/** Signature node */
	public static final int SIGNATURE_NODE = 16;
	/** Disabled signature node */
	public static final int DISABLED_SIGNATURE_NODE = 17;
	/** User Attribute node */
	public static final int USER_ATTRIBUTE_NODE = 18;
	/** disabled user Attribute node */
	public static final int DISABLED_USER_ATTRIBUTE_NODE = 19;
	
	/** method to return the type of icon that this node requires
	 * @return the icon type 
	 */
	public int getIconType();
	
}
