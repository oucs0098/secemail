/*
 * SubkeyGenStatusDlg.java
 *
 * Created on 12 July 2007, 10:25
 */
package ui;

import openpgp.keystore.model.PrimarySigningKey;
import core.keyhandlers.*;
import core.keyhandlers.parameters.*;
import core.algorithmhandlers.keymaterial.*;
import core.algorithmhandlers.openpgp.util.*;
import java.security.*;
import java.util.Date;

/** Dialog to generate a subkey
 * @version $Id: SubkeyGenStatusDlg.java,v 1.6 2007-08-10 17:08:25 nigelb Exp $
 */
public class SubkeyGenStatusDlg extends javax.swing.JDialog {
    
    /** A nested class that generates a new subkey on a separate thread. */
    public class SubkeyGenerator implements Runnable {
        private int symmetricAlg;
        private int ska;
        private int skaKeysize;
        private byte [] passphrase;
        private KeyHandler pubkeyring;
        private KeyHandler seckeyring;
        private PrimarySigningKey psk;
        private KeyData [] keys;
        private OpenPGPAddKeyParameters pubparam[];
        private OpenPGPAddSecretKeyParameters secparam[];

        public SubkeyGenerator(KeyHandler pubkeyring, KeyHandler seckeyring, 
        		PrimarySigningKey psk, int symmetricAlg, int ska, int skaKeysize,
        		byte[] passphrase) {
        	this.pubkeyring = pubkeyring;  // public keyring
        	this.seckeyring = seckeyring;  // secret keyring
        	this.psk = psk;  // the signing key
            this.symmetricAlg = symmetricAlg;  // symmetric algorithm to use
            this.ska = ska;  // subkey algorithm
            this.skaKeysize = skaKeysize;  // subkey algorithm key size
            this.passphrase = passphrase;  // passphrase for the signing key
        }
        
        public void run() {
            try {
            	// Get the time, for generating the correct key creation time
                Date now = new Date(); 
                
                // set up default key size if necessary
                if (skaKeysize == 0) {
                    skaKeysize = PublicKeyAlgorithmSettings.getDefaultKeySize(ska);
                }
                
                setVisible(true);
                setCursor(new java.awt.Cursor(java.awt.Cursor.WAIT_CURSOR));

                setStatusText("Generating subkey (this may take some time)...");
                setIndeterminate(true);

                // init
                AsymmetricAlgorithmParameters[] keymaterial = 
                        new AsymmetricAlgorithmParameters[1];
                keys = new KeyData[1];

                pubparam = new OpenPGPAddKeyParameters[1];
                secparam = new OpenPGPAddSecretKeyParameters[1];
                
                // generate subkey
                if ((ska == PublicKeyAlgorithmSettings.RSA_ENCRYPTSIGN) || (ska == PublicKeyAlgorithmSettings.RSA_ENCRYPT)) {
                    keymaterial[0] = new RSAAlgorithmParameters();
                    keymaterial[0].generateKeyPair(skaKeysize, SecureRandom.getInstance("SHA1PRNG"));
                    keys[0] = new KeyData(keymaterial[0]);
                } else if (ska == PublicKeyAlgorithmSettings.ELGAMAL_ENCRYPT) {
                    keymaterial[0] = new ElGamalAlgorithmParameters();
                    keymaterial[0].generateKeyPair(skaKeysize, SecureRandom.getInstance("SHA1PRNG"));
                    keys[0] = new KeyData(keymaterial[0]);
                } else {
                    throw new Exception("Encryption algorithm is not supported.");
                }
                
                // save new key
                pubparam[0] = new OpenPGPAddKeyParameters(now, ska, 
                		psk.getPublicKeyPacket().getAlgorithm(), null, null,
                		null);
                secparam[0] = new OpenPGPAddSecretKeyParameters(now, 
                		ska, psk.getPublicKeyPacket().getAlgorithm(), null,
                		null, null, passphrase, symmetricAlg, 
                		HashAlgorithmSettings.SHA1);
 
                setIndeterminate(false);
                setValue(50);
                setStatusText("Saving keys...");

                pubkeyring.addKeys(keys, null, pubparam);
                setValue(75);
                seckeyring.addKeys(keys, null, secparam);
                setValue(100);

                setStatusText("Done");
                
            } catch (Exception e) {
            	e.printStackTrace();
                setStatusText("Error!");
                System.out.println(e.getMessage());
                javax.swing.JOptionPane.showMessageDialog(null, e.getMessage(),
						"Problem", javax.swing.JOptionPane.ERROR_MESSAGE);
            }

            setCursor(new java.awt.Cursor(java.awt.Cursor.DEFAULT_CURSOR));
            setVisible(false);
        }
    }
    
    /** Creates new form OpenPGPKeyGenDlg */
    public SubkeyGenStatusDlg(java.awt.Frame parent, boolean modal) {
        super(parent, modal);
        initComponents();
    }
    
    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    // <editor-fold defaultstate="collapsed" desc=" Generated Code ">//GEN-BEGIN:initComponents
    private void initComponents() {
        jPanel1 = new javax.swing.JPanel();
        jPanel2 = new javax.swing.JPanel();
        subkeyGenProgressBar = new javax.swing.JProgressBar();
        jPanel3 = new javax.swing.JPanel();
        subkeyGenLabel = new javax.swing.JLabel();

        setDefaultCloseOperation(javax.swing.WindowConstants.DO_NOTHING_ON_CLOSE);
        setTitle("Generating subkey...");
        setResizable(false);
        jPanel1.setLayout(new java.awt.BorderLayout());

        jPanel1.setPreferredSize(new java.awt.Dimension(330, 100));
        subkeyGenProgressBar.setIndeterminate(true);
        subkeyGenProgressBar.setPreferredSize(new java.awt.Dimension(250, 14));
        jPanel2.add(subkeyGenProgressBar);

        jPanel1.add(jPanel2, java.awt.BorderLayout.SOUTH);

        jPanel3.add(subkeyGenLabel);

        jPanel1.add(jPanel3, java.awt.BorderLayout.CENTER);

        getContentPane().add(jPanel1, java.awt.BorderLayout.CENTER);

        pack();
    }// </editor-fold>//GEN-END:initComponents
    
    /** Closes the dialog */
    private void closeDialog(java.awt.event.WindowEvent evt) {                             
        setVisible(false);
        dispose();
    }
    
    public void setMaximum(int max) {
        subkeyGenProgressBar.setMaximum(max);
    }
    
    public void setMinimum(int min) {
        subkeyGenProgressBar.setMinimum(min);
    }
    
    public void setValue(int n) {
        subkeyGenProgressBar.setValue(n);
    }
    
    public void setIndeterminate(boolean newValue) {
        subkeyGenProgressBar.setIndeterminate(newValue);
    }
    
    public void setStatusText(String text) {
        subkeyGenLabel.setText(text);
    }
    
    public void generateOpenPGPSubkey(KeyHandler pubkeyring,
			KeyHandler seckeyring, PrimarySigningKey psk, int symmetricAlg,
            int ska, int skaKeysize, byte[] passphrase) throws Exception {

        SubkeyGenerator r = new SubkeyGenerator(pubkeyring, seckeyring, psk,
        		symmetricAlg, ska, skaKeysize, passphrase);

        Thread thread = new Thread(r);
        thread.start();
    }
    
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JPanel jPanel3;
    private javax.swing.JLabel subkeyGenLabel;
    private javax.swing.JProgressBar subkeyGenProgressBar;
    // End of variables declaration//GEN-END:variables
    
}
