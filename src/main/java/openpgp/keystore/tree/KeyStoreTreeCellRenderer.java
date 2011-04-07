package openpgp.keystore.tree;

import java.awt.Color;
import java.awt.Component;
import java.awt.Font;
import javax.swing.tree.*;
import javax.swing.*;

import openpgp.keystore.*;
import openpgp.keystore.model.*;

/** Renderer to render icons in the JTree according to the node type 
 * @version $Id: KeyStoreTreeCellRenderer.java,v 1.7 2007-08-22 22:01:12 nigelb Exp $
 */
public class KeyStoreTreeCellRenderer extends DefaultTreeCellRenderer {

	// Icons
	private Icon rsaKeypairIcon;
	private Icon rsaDisabledKeypairIcon;
	private Icon rsaPublicKeyIcon;
	private Icon rsaDisabledPublicKeyIcon;
	private Icon dsaKeypairIcon;
	private Icon dsaDisabledKeypairIcon;
	private Icon dsaPublicKeyIcon;
	private Icon dsaDisabledPublicKeyIcon;
	private Icon elGamalKeypairIcon;
	private Icon elGamalDisabledKeypairIcon;
	private Icon elGamalPublicKeyIcon;
	private Icon elGamalDisabledPublicKeyIcon;
	private Icon userIDIcon;
	private Icon disabledUserIDIcon;
	private Icon signatureIcon;
	private Icon disabledSignatureIcon;
	private Icon userAttributeIcon;
	// background colours
	private Color defaultBackground;
	private Color untrustedBackground;
	private Color partiallyTrustedBackground;
	private Color trustedBackground;
	// whether to display colour
	private boolean showColour = true;
	
	public KeyStoreTreeCellRenderer(boolean showColour) {
		// set up the rendering properties
		this.showColour = showColour;
		// load up the icons
        IconLoader loader = IconLoader.getInstance();
        rsaKeypairIcon = loader.getIcon("rsakeypair32x16.gif");
        rsaDisabledKeypairIcon = loader.getIcon("rsakeypair32x16disabled.gif");
        rsaPublicKeyIcon = loader.getIcon("rsakey32x16.gif");
        rsaDisabledPublicKeyIcon = loader.getIcon("rsakey32x16disabled.gif");
        dsaKeypairIcon = loader.getIcon("dsakeypair32x16.gif");
        dsaDisabledKeypairIcon = loader.getIcon("dsakeypair32x16disabled.gif");
        dsaPublicKeyIcon = loader.getIcon("dsakey32x16.gif");
        dsaDisabledPublicKeyIcon = loader.getIcon("dsakey32x16disabled.gif");
        elGamalKeypairIcon = loader.getIcon("elgkeypair32x16.gif");
        elGamalDisabledKeypairIcon = loader.getIcon("elgkeypair32x16disabled.gif");
        elGamalPublicKeyIcon = loader.getIcon("elgkey32x16.gif");
        elGamalDisabledPublicKeyIcon = loader.getIcon("elgkey32x16disabled.gif");
        userIDIcon = loader.getIcon("email20x16.gif");
        disabledUserIDIcon = loader.getIcon("email20x16disabled.gif");
        signatureIcon = loader.getIcon("sig26x16.gif");
        disabledSignatureIcon = loader.getIcon("sig26x16disabled.gif");
        userAttributeIcon = loader.getIcon("userattribute20x16.gif");
        // set up the background colours
        untrustedBackground = new Color(255, 179, 179);  // red-ish
        partiallyTrustedBackground = new Color(255, 219, 184);  // amber-ish 
        trustedBackground = new Color(219, 255, 184);  // green-ish
	}
	
	/**
	 * @see javax.swing.tree.DefaultTreeCellRenderer#getTreeCellRendererComponent(
	 * 		javax.swing.JTree, java.lang.Object, boolean, boolean, boolean, int,
	 *  	boolean)
	 */
	public Component getTreeCellRendererComponent(JTree tree, Object value,
			boolean sel, boolean expanded, boolean leaf, int row,
			boolean hasFocus) {
		// make sure all the defauts are set up
		super.getTreeCellRendererComponent(tree, value, sel, expanded, leaf,
				row, hasFocus);
		KeyStoreNode node = (KeyStoreNode)value;
        switch (node.getIconType()) {
            case KeyStoreNode.RSA_KEY_PAIR_NODE:
                setIcon(rsaKeypairIcon);
                setToolTipText("RSA Public/Private Keypair");
                break;
            case KeyStoreNode.RSA_DISABLED_KEY_PAIR_NODE:
            	setIcon(rsaDisabledKeypairIcon);
                setToolTipText("RSA Public/Private Keypair");
            	break;
            case KeyStoreNode.RSA_PUBLIC_KEY_NODE:
                setIcon(rsaPublicKeyIcon);
                setToolTipText("RSA Public Key");
                break;
            case KeyStoreNode.RSA_DISABLED_PUBLIC_KEY_NODE:
            	setIcon(rsaDisabledPublicKeyIcon);
                setToolTipText("RSA Public Key");
            	break;
            case KeyStoreNode.DSA_KEY_PAIR_NODE:
                setIcon(dsaKeypairIcon);
                setToolTipText("DSA Public/Private Keypair");
                break;
            case KeyStoreNode.DSA_DISABLED_KEY_PAIR_NODE:
            	setIcon(dsaDisabledKeypairIcon);
                setToolTipText("DSA Public/Private Keypair");
            	break;
            case KeyStoreNode.DSA_PUBLIC_KEY_NODE:
                setIcon(dsaPublicKeyIcon);
                setToolTipText("DSA Public Key");
                break;
            case KeyStoreNode.DSA_DISABLED_PUBLIC_KEY_NODE:
            	setIcon(dsaDisabledPublicKeyIcon);
                setToolTipText("DSA Public Key");
            	break;
            case KeyStoreNode.ELGAMAL_KEY_PAIR_NODE:
                setIcon(elGamalKeypairIcon);
                setToolTipText("El Gamal Public/Private Keypair");
                break;
            case KeyStoreNode.ELGAMAL_DISABLED_KEY_PAIR_NODE:
            	setIcon(elGamalDisabledKeypairIcon);
                setToolTipText("El Gamal Public/Private Keypair");
            	break;
            case KeyStoreNode.ELGAMAL_PUBLIC_KEY_NODE:
                setIcon(elGamalPublicKeyIcon);
                setToolTipText("El Gamal Public Key");
                break;
            case KeyStoreNode.ELGAMAL_DISABLED_PUBLIC_KEY_NODE:
            	setIcon(elGamalDisabledPublicKeyIcon);
                setToolTipText("El Gamal Public Key");
            	break;
            case KeyStoreNode.SIGNATURE_NODE:
                setIcon(signatureIcon);
                setToolTipText("User-Key Binding Signature");
                break;
            case KeyStoreNode.DISABLED_SIGNATURE_NODE:
                setIcon(disabledSignatureIcon);
                setToolTipText("User-Key Binding Signature");
                break;
            case KeyStoreNode.USER_ID_NODE:
                setIcon(userIDIcon);
                setToolTipText("User Identifier");
                break;
            case KeyStoreNode.USER_ATTRIBUTE_NODE:
            	setIcon(userAttributeIcon);
                setToolTipText("User Photograph");
                break;
            case KeyStoreNode.DISABLED_USER_ID_NODE:
                setIcon(disabledUserIDIcon);
                setToolTipText("User Identifier");
                break;
            case KeyStoreNode.KEYRING_NODE:
            	KeyStore ks = (KeyStore)node;
            	if (ks.isLeaf()) {
            		setIcon(closedIcon);
            	}
                break;
        }
        if (showColour) colourise(node);
        
        // italicise the font if the signature or subkey is invalid
        Font f = getFont();
    	if (node instanceof Signature && !((Signature)node).isVerified()) {
    		setFont(new Font(f.getName(), Font.ITALIC, f.getSize()));
    	} else if (node instanceof Subkey && !((Subkey)node).isVerified()) {
    		setFont(new Font(f.getName(), Font.ITALIC, f.getSize()));
    	} else {
    		setFont(new Font(f.getName(), Font.PLAIN, f.getSize()));
    	}
        
		return this;
	}
	
	private void colourise(KeyStoreNode node) {
		// set up the local default background colour first time in this method
		if (defaultBackground == null) 
			defaultBackground = getBackgroundNonSelectionColor();
        // set the background colour for this node
        if (node instanceof KeyStore) {  // key store can have default background
        	this.setBackgroundNonSelectionColor(defaultBackground);
        } else {
        	Trustable trustable = (Trustable)node;
        	int trustValue = KeyStoreTrustManager.getTrustValue(trustable);
        	if (node instanceof UserObject) {
        		switch(trustValue) {
	        		case TrustValues.KEYLEGIT_UNDEFINED:
	        		case TrustValues.KEYLEGIT_NOT_TRUSTED:
	        			this.setBackgroundNonSelectionColor(
	        					untrustedBackground);
	        			break;
	        		case TrustValues.KEYLEGIT_MARGINALLY_TRUSTED:
	        			this.setBackgroundNonSelectionColor(
	        					partiallyTrustedBackground);
	        			break;
	        		case TrustValues.KEYLEGIT_COMPLETELY_TRUSTED:
	        			this.setBackgroundNonSelectionColor(
	        					trustedBackground);
	        			break;
        		}
            } else {
            	switch(trustValue) {
            		case TrustValues.OWNERTRUST_UNDEFINED:
	        		case TrustValues.OWNERTRUST_UNKNOWN:
	        		case TrustValues.OWNERTRUST_NOT_USUALLY_TRUSTED:
	        			this.setBackgroundNonSelectionColor(
	        					untrustedBackground);
	        			break;
	        		case TrustValues.OWNERTRUST_USUALLY_TRUSTED:
	        			this.setBackgroundNonSelectionColor(
	        					partiallyTrustedBackground);
	        			break;
	        		case TrustValues.OWNERTRUST_ALWAYS_TRUSTED:
	        		case TrustValues.OWNERTRUST_ULTIMATE_TRUST:
	        			this.setBackgroundNonSelectionColor(
	        					trustedBackground);
	        			break;
	    		}
            }
        }
	}

	/** @return the DSA keypair icon */
	public Icon getDSAKeypairIcon() {
		return dsaKeypairIcon;
	}

	/** @return the DSA public key icon */
	public Icon getDSAPublicKeyIcon() {
		return dsaPublicKeyIcon;
	}

	/** @return the RSA keypair icon */
	public Icon getRSAKeypairIcon() {
		return rsaKeypairIcon;
	}

	/** @return the RSA public key icon */
	public Icon getRSAPublicKeyIcon() {
		return rsaPublicKeyIcon;
	}

	/** @return the signature icon  */
	public Icon getSignatureIcon() {
		return signatureIcon;
	}

	/** @return the user ID icon */
	public Icon getUserIDIcon() {
		return userIDIcon;
	}

	/** @return the DSA disabled keypair icon */
	public Icon getDSADisabledKeypairIcon() {
		return dsaDisabledKeypairIcon;
	}

	/** @return the DSA disabled public key icon */
	public Icon getDSADisabledPublicKeyIcon() {
		return dsaDisabledPublicKeyIcon;
	}

	/** @return the RSA disabled keypair icon */
	public Icon getRSADisabledKeypairIcon() {
		return rsaDisabledKeypairIcon;
	}

	/** @return the RSA disabled public key icon */
	public Icon getRSADisabledPublicKeyIcon() {
		return rsaDisabledPublicKeyIcon;
	}

	/** @return the disabled signature icon */
	public Icon getDisabledSignatureIcon() {
		return disabledSignatureIcon;
	}

	/** @return the disabled user ID icon */
	public Icon getDisabledUserIDIcon() {
		return disabledUserIDIcon;
	}

	/** @return the El Gamal disabled keypair icon  */
	public Icon getElGamalDisabledKeypairIcon() {
		return elGamalDisabledKeypairIcon;
	}

	/** @return the El Gamal disabled public key icon */
	public Icon getElGamalDisabledPublicKeyIcon() {
		return elGamalDisabledPublicKeyIcon;
	}

	/** @return the El Gamal keypair icon */
	public Icon getElGamalKeypairIcon() {
		return elGamalKeypairIcon;
	}

	/** @return the El Gamal public key icon */
	public Icon getElGamalPublicKeyIcon() {
		return elGamalPublicKeyIcon;
	}

	/** @return the user attribute icon */
	public Icon getUserAttributeIcon() {
		return userAttributeIcon;
	}
	
}
