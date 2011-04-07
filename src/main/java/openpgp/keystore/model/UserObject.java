package openpgp.keystore.model;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Vector;

import javax.swing.tree.MutableTreeNode;
import javax.swing.tree.TreeNode;

import core.algorithmhandlers.openpgp.OpenPGPPacketOutputStream;
import core.algorithmhandlers.openpgp.packets.SignaturePacket;
import core.algorithmhandlers.openpgp.packets.TrustPacket;
import core.algorithmhandlers.openpgp.packets.Packet;
import core.exceptions.AlgorithmException;

/** Class to abstract out common user object functionality
 * @version $Id: UserObject.java,v 1.2 2007-08-25 14:06:06 nigelb Exp $
 */
public abstract class UserObject implements ExportableKeyringPacketWrapper, 
		Signable, KeyStoreNode {
	
    // The wrapped packet
	protected Packet userPacket;
    // The trust assigned to this object (app-calculated)
    protected TrustPacket trustPacket;
    // The parent node
    protected TreeNode parentNode;
    // The signatures verifying this user object
    protected Vector signatures = new Vector();
    // Whether the self-signature has been revoked
	protected boolean isSelfSignatureRevoked;
	// The key that this user object is bound to
	protected PrimarySigningKey signingKey;
    
    /** Adds a signature computed over the user and the key, applying special
     * handling for certification revocation signatures.
     * @param The signature to add 
     */
	public void addSignature(Signature signature) {
		if (signature.getSignatureType() == SignaturePacket.CERT_REVOCATION) {
    		// find the revoked signature, and process it
    		String revokingKeyID = signature.getSigningKeyLongID();
    		Date revokingDate = signature.getCreationDate();
    		boolean matchFound = false;
    		for (int i = 0; i < signatures.size(); ++i) {
    			Signature sig = (Signature)signatures.elementAt(i);
    			int sigType = sig.getSignatureType();
    			// look for signature type 0x10, 0x11, 0x12, or 0x13
    			// where the key IDs match, and the matching signature was
    			// made before the revoking signature ...
    			if (sigType >= SignaturePacket.GENERIC_UID &&
    					sigType <= SignaturePacket.POSITIVE_UID &&
    					revokingKeyID.equals(sig.getSigningKeyLongID()) &&
    					sig.getCreationDate().before(revokingDate)) {
    				// it's a positive match ...
    				sig.setRevocationSignature(signature);
    				// if the original signature was a self-signature and was 
    				// validated ok, mark this user attribute as revoked
    				if (sig.isSelfSignature() && sig.isRevoked()) 
    					isSelfSignatureRevoked = true;
    				matchFound = true;
    			}
    		}
    		if (!matchFound) {
    			System.err.println("Error: match not found for certificate " +
    					"revocation signature. Key ID: " + 
    					signature.getSigningKeyLongID());
    		}
    	} else {  // add signature to the tree, determine whether self-signature
    		signature.setParent(this);
            signatures.add(signature);
            String parentKeyID = ((PrimarySigningKey)getParent()).getLongKeyID();
            if (signature.getSigningKeyLongID().equals(parentKeyID)) {
            	signature.setSelfSignature(true);
            }
    	}
	}

	/** @return an iterator to iterate over the signature objects */
    public Iterator getSignatureIterator() {
        return signatures.iterator();
    }
    
    /** a list to use for storing self-signatures, for local use only */
    private List selfSignatures = new ArrayList();
    
    /** Method to get the most recent self-signature. From the latest (at the
     * time of writing) internet draft (section 5.2.3.3):
     * "An implementation that encounters multiple self-signatures on the same 
     * object may resolve the ambiguity in any way it sees fit, but it is 
     * RECOMMENDED that priority be given to the most recent self-signature." 
     * There should be at least one self-signature on a user object - once 
     * revoked, the user object owning that self-signature should no longer 
     * be signable, so no further self-signatures should be applicable (at 
     * least in this implementation). For imported keys the implementation
     * should be more accommodating.
     * @return the most recent self-signature, or null if not found 
     */
    public Signature getSelfSignature() {
    	Signature ss = null;
    	selfSignatures.clear();
        for (int i = 0; i < signatures.size(); ++i) {
        	Signature s = (Signature)signatures.elementAt(i);
        	if (s.isSelfSignature()) {
        		selfSignatures.add(s);
        	}
        }
        int numSelfSigs = selfSignatures.size();
        if (numSelfSigs > 0) {
        	ss = (Signature)selfSignatures.get(0);
        	if (numSelfSigs > 1) {
	        	for (int i = 1; i < numSelfSigs; ++i) {
	        		Signature tmp = (Signature)selfSignatures.get(i);
	        		if (tmp.getCreationDate().compareTo(ss.getCreationDate()) > 0) {
	        			ss = tmp;
	        		}
	        	}
        	}
        }
        return ss;
    }
    
    /** @param out output stream to which wrapped object should be written */
	public void writePublicKeyringPacket(OpenPGPPacketOutputStream out,
			boolean includeTrust) throws IOException, AlgorithmException {
		out.writePacket(userPacket);
		if (includeTrust && trustPacket != null) 
			out.writePacket(trustPacket);
	}
	
	/** @param out output stream to which wrapped object should be written */
	public void writePrivateKeyringPacket(OpenPGPPacketOutputStream out,
			boolean includeTrust) throws IOException, AlgorithmException {
		// private export for this class is the same as public export
		this.writePublicKeyringPacket(out, includeTrust);
	}
	
	/** Method to allow the re-setting of the user ID using the primary key 
	 * during a keyring merge (also gives the signature the new top-level 
	 * signing key).
	 * @param signingKey the signingKey to set
	 */
	void setPrimarySigningKey(PrimarySigningKey signingKey) {
		this.signingKey = signingKey;
		for (int i = 0; i < signatures.size(); ++i) {
			((Signature)signatures.elementAt(i)).setSigningUserID(signingKey);
		}
	}

	/** @param trustPkt The trust packet denoting the attribute trust */
    public void setTrust(TrustPacket trustPkt) {
    	trustPacket = trustPkt;
    }
    
    /** @return The trust packet denoting the attribute trust */
    public TrustPacket getTrust() {
        return trustPacket;
    }

	/** Resets the user object of the receiver to object. */
	public void setUserObject(Object object) {
		throw new UnsupportedOperationException();
	}
	
	/** Adds child to the receiver at index. */
	public void insert(MutableTreeNode child, int index) {
		signatures.insertElementAt(child, index);
	}

	/** Removes the child at index from the receiver. */
	public void remove(int index) {
		signatures.remove(index);
	}

	/** Removes node from the receiver. */
	public void remove(MutableTreeNode node) {
		signatures.remove(node);
	}

	/** Removes the receiver from its parent. */
	public void removeFromParent() {
		MutableTreeNode node = (MutableTreeNode)getParent();
		if (node != null) {
			node.remove(this);
		}
	}

	/** Method to set the parent of this node, required for tree traversal
	 * @param newParent The ancestor node in the hierarchy 
	 */
	public void setParent(MutableTreeNode newParent) {
		this.parentNode = newParent;
	}
	
	/** @see javax.swing.tree.TreeNode#children() */
	public Enumeration children() {
		return signatures.elements();
	}

	/**@see javax.swing.tree.TreeNode#getAllowsChildren() */
	public boolean getAllowsChildren() {
		return true;
	}

	/** @see javax.swing.tree.TreeNode#getChildAt(int) */
	public TreeNode getChildAt(int childIndex) {
		return (TreeNode)signatures.elementAt(childIndex);
	}

	/** @see javax.swing.tree.TreeNode#getChildCount() */
	public int getChildCount() {
		return signatures.size();
	}

	/** @see javax.swing.tree.TreeNode#getIndex(javax.swing.tree.TreeNode) */
	public int getIndex(TreeNode node) {
		return signatures.indexOf(node);
	}

	/** @see javax.swing.tree.TreeNode#getParent() */
	public TreeNode getParent() {
		return parentNode;
	}

	/** @see javax.swing.tree.TreeNode#isLeaf() */
	public boolean isLeaf() {
		return signatures.isEmpty();
	}
	
	/** @return the isSelfSignatureRevoked */
	public boolean isSelfSignatureRevoked() {
		return isSelfSignatureRevoked;
	}

}
