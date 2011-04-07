/*
 * Oxford Brookes University Secure Email Proxy
 * Copyright (C) 2002/3 Oxford Brookes University Secure Email Project
 * http://secemail.brookes.ac.uk
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * The Secure Email Project is:
 *
 * Marcus Povey <mpovey@brookes.ac.uk> or <icewing@dushka.co.uk>
 * Damian Branigan <dbranigan@brookes.ac.uk>
 * George Davson <gdavson@brookes.ac.uk>
 * David Duce <daduce@brookes.ac.uk>
 * Simon Hogg <simon.hogg@brookes.ac.uk>
 * Faye Mitchell <frmitchell@brookes.ac.uk>
 *
 * For further information visit the secure email project website.
 */
package ui;

import openpgp.keystore.util.StringHelper;
import core.exceptions.*; 
import core.keyhandlers.*;
import core.keyhandlers.identifiers.*;
import core.keyhandlers.keydata.*;
import core.keyhandlers.parameters.*;
import core.algorithmhandlers.keymaterial.*;
import core.algorithmhandlers.openpgp.util.*;
import javax.swing.JFileChooser;

/**
 * <p>A class to add or edit an OpenPGP key source.</p>
 */
public class EditKeySource extends javax.swing.JDialog {
    
    /** Creates new form EditKeySource */
    public EditKeySource(java.awt.Frame parent, boolean modal, KeyHandler keysource) {
        super(parent, modal);
        initComponents();
        java.awt.Dimension screenSize = 
                java.awt.Toolkit.getDefaultToolkit().getScreenSize();
        java.awt.Dimension dialogSize = getSize();
        setLocation((screenSize.width-dialogSize.width)/2,
                (screenSize.height-dialogSize.height)/2);
        returnValue = keysource;
        
        typeServer.setVisible(false);
        typeFile.setVisible(false);
        
        jTextField1.setText(keysource.getDescription());
        
        if (returnValue instanceof KeyFile) {
            typeFile.setVisible(true);
            
            KeyFile kf = (KeyFile)returnValue;
            jTextField4.setText(StringHelper.reduceWinPath(kf.getFileName()));
        } else if (returnValue instanceof KeyServer) {
            typeServer.setVisible(true);
            
            KeyServer ks = (KeyServer)returnValue;
            jTextField3.setText(ks.getServerAddress());
            jTextField2.setText(Integer.toString(ks.getServerPort()));
        }
        
    }
    
    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    // <editor-fold defaultstate="collapsed" desc=" Generated Code ">//GEN-BEGIN:initComponents
    private void initComponents() {
        jPanel1 = new javax.swing.JPanel();
        jButton1 = new javax.swing.JButton();
        jButton2 = new javax.swing.JButton();
        jPanel2 = new javax.swing.JPanel();
        jPanel3 = new javax.swing.JPanel();
        jLabel1 = new javax.swing.JLabel();
        jTextField1 = new javax.swing.JTextField();
        typeServer = new javax.swing.JPanel();
        jPanel4 = new javax.swing.JPanel();
        jLabel2 = new javax.swing.JLabel();
        jTextField2 = new javax.swing.JTextField();
        jPanel5 = new javax.swing.JPanel();
        jLabel3 = new javax.swing.JLabel();
        jTextField3 = new javax.swing.JTextField();
        typeFile = new javax.swing.JPanel();
        jPanel6 = new javax.swing.JPanel();
        jLabel4 = new javax.swing.JLabel();
        jTextField4 = new javax.swing.JTextField();
        jButton3 = new javax.swing.JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
        setTitle("Edit Key Source");
        setModal(true);
        addWindowListener(new java.awt.event.WindowAdapter() {
            public void windowClosing(java.awt.event.WindowEvent evt) {
                closeDialog(evt);
            }
        });

        jButton1.setMnemonic('o');
        jButton1.setText("Ok");
        jButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton1ActionPerformed(evt);
            }
        });

        jPanel1.add(jButton1);

        jButton2.setMnemonic('c');
        jButton2.setText("Cancel");
        jButton2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton2ActionPerformed(evt);
            }
        });

        jPanel1.add(jButton2);

        getContentPane().add(jPanel1, java.awt.BorderLayout.SOUTH);

        jPanel2.setPreferredSize(new java.awt.Dimension(400, 120));
        jLabel1.setText("Type");
        jPanel3.add(jLabel1);

        jTextField1.setColumns(25);
        jTextField1.setEditable(false);
        jPanel3.add(jTextField1);

        jPanel2.add(jPanel3);

        typeServer.setLayout(new java.awt.BorderLayout());

        jLabel2.setText("Port");
        jPanel4.add(jLabel2);

        jTextField2.setColumns(5);
        jPanel4.add(jTextField2);

        typeServer.add(jPanel4, java.awt.BorderLayout.CENTER);

        jLabel3.setText("Address");
        jPanel5.add(jLabel3);

        jTextField3.setColumns(20);
        jPanel5.add(jTextField3);

        typeServer.add(jPanel5, java.awt.BorderLayout.NORTH);

        jPanel2.add(typeServer);

        jLabel4.setText("Filename");
        jPanel6.add(jLabel4);

        jTextField4.setColumns(20);
        jPanel6.add(jTextField4);

        jButton3.setText("Browse...");
        jButton3.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton3ActionPerformed(evt);
            }
        });

        jPanel6.add(jButton3);

        typeFile.add(jPanel6);

        jPanel2.add(typeFile);

        getContentPane().add(jPanel2, java.awt.BorderLayout.CENTER);

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void jButton3ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton3ActionPerformed
// TODO add your handling code here:
        // browse for a file
        JFileChooser chooser = new JFileChooser();
        
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        chooser.setFileHidingEnabled(true);
        chooser.setMultiSelectionEnabled(false);
        
        int returnVal = chooser.showOpenDialog(null);
        if (returnVal == JFileChooser.APPROVE_OPTION) {
           jTextField4.setText(chooser.getSelectedFile().getAbsolutePath());
        }
    }//GEN-LAST:event_jButton3ActionPerformed

    private void closeDialog(java.awt.event.WindowEvent evt) {//GEN-FIRST:event_closeDialog
        setVisible(false);
        dispose();
    }//GEN-LAST:event_closeDialog

    private void jButton2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton2ActionPerformed
// Add your handling code here:
        setVisible(false);
        dispose();
    }//GEN-LAST:event_jButton2ActionPerformed

    private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton1ActionPerformed
// Add your handling code here:
        
        if (returnValue instanceof KeyFile) {
            KeyFile kf = (KeyFile)returnValue;
            
            kf.setFile(StringHelper.escapeWinPath(jTextField4.getText()));
        } else if (returnValue instanceof KeyServer) {
            KeyServer ks = (KeyServer)returnValue;
            
            int port = 0;
            try {
                port = Integer.parseInt(jTextField2.getText());
            } catch (NumberFormatException n) {
                port = 0;
            }
            
            ks.setServer(jTextField3.getText(), port);
        }
        
        setVisible(false);
        dispose();
    }//GEN-LAST:event_jButton1ActionPerformed

    public KeyHandler getReturnValue() {
        return returnValue;
    }
    
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton jButton1;
    private javax.swing.JButton jButton2;
    private javax.swing.JButton jButton3;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JPanel jPanel3;
    private javax.swing.JPanel jPanel4;
    private javax.swing.JPanel jPanel5;
    private javax.swing.JPanel jPanel6;
    private javax.swing.JTextField jTextField1;
    private javax.swing.JTextField jTextField2;
    private javax.swing.JTextField jTextField3;
    private javax.swing.JTextField jTextField4;
    private javax.swing.JPanel typeFile;
    private javax.swing.JPanel typeServer;
    // End of variables declaration//GEN-END:variables
    private KeyHandler returnValue;
}
