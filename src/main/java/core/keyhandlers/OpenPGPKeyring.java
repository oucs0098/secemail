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

package core.keyhandlers;
import core.algorithmhandlers.openpgp.*;
import core.algorithmhandlers.openpgp.packets.*;
import core.algorithmhandlers.openpgp.packets.v4signature.*;
import core.algorithmhandlers.openpgp.util.*;
import core.keyhandlers.parameters.*;
import core.keyhandlers.identifiers.*;
import core.keyhandlers.keydata.*;
import core.exceptions.*;
import java.security.SecureRandom;
import java.security.PrivateKey;
import java.io.*;
import java.util.*;

/**
 * <p>Defines base functionality for OpenPGP keyrings.</p>
 */
public abstract class OpenPGPKeyring extends KeyFile {
    
    /** Creates a new instance of OpenPGPKeyring */
    public OpenPGPKeyring() {
    }
    
    /** Creates a new instance of OpenPGPKeyring */
    public OpenPGPKeyring(String filename, KeyHandlerParameters parameters) {
        super(filename, parameters);
    }
    
/* Search utility methods ************************************************************/
    
    
    /**
     * <p>Delete a key matching the given id from a given key store.</p>
     * <p>This method will remove all keys (with their subkeys) matching the KeyIdentifier object from the key store, and so
     * care should be taken to be as specific as possible!</p>
     * <p>If the key you delete is a primary key then all its sub keys are removed, if you specify a sub key then only that key is
     * removed.</p>
     * <p>If duplicate prime keys are found then only the first one encountered is removed. To remove all keys matching a given ID you
     * should run this method multiple times until it returns 0.</p>
     * @param id A KeyIdentifier object specifying the key(s) to remove.
     * @param parameters Any extra parameters needed, for example pass phrases for secret key stores etc, may be null.
     * @return The number of keys removed.
     * @throws KeyHandlerException if something went wrong.
     */
    public int removeKeys(KeyIdentifier id, KeyHandlerParameters parameters) throws KeyHandlerException {
        int numDeleted = 0;
        
        try {
            // create temp files
            File keyring = new File(getFileName());
            File tmp = new File(keyring.getAbsoluteFile().getParentFile(), "sep" + generateNumber() + ".tmp");
            
            // begin processing file
            OpenPGPPacketInputStream in = new OpenPGPPacketInputStream(new FileInputStream(keyring));            
            OpenPGPPacketOutputStream out = new OpenPGPPacketOutputStream(new FileOutputStream(tmp));
    
            Packet p = null;
            do {
                p = in.readPacket();
                
                if (p!=null) {
                    
                    if (p instanceof KeyPacket) {
                        KeyPacket k = (KeyPacket)p;
                        
                        // how are we searching for key?
                        if (id instanceof OpenPGPStandardKeyIdentifier) {
                            // Searching using standard "user <address@example.com>"
                            
                            Vector tmpstore = new Vector();
                            
                            if (!isSubKey(p)) {
                                // this is a primary key, perform further analysis
                            
                                tmpstore.add(p); // save key
                                
                                // skip packets until i get to a user ID packet
                                do {
                                    p = in.readPacket();
                                    tmpstore.add(p);
                                    
                                    if (p == null) // reached the end of the keyring before finding a key ID
                                        throw new KeyHandlerException("Invalid keyring");
                                    
                                } while (!(p instanceof UserIDPacket));
                                
                                // is this the key we were looking for?
                                UserIDPacket uid = (UserIDPacket)p;
                                if (compareByteArrays(uid.getID(), id.getDefaultID())) {
                                    // yes
                                    numDeleted++;
                                    
                                    do {
                                        p = in.readPacket();
                                        if ((p!=null) && (isSubKey(p))) {
                                            numDeleted++;
                                        }
                                    } while ((p!=null) && ( (!(p instanceof KeyPacket)) || (isSubKey(p))));
                                    
                                    // if not null then we have the next key, write it out
                                    if (p!=null) out.writePacket(p);
                                    
                                } else {
                                    // no
                                    for (int n = 0; n < tmpstore.size(); n++) 
                                        out.writePacket((Packet)tmpstore.elementAt(n));
                                }
                                
                            } else {
                                // is a subkey, just write out
                                out.writePacket(p);
                            }
                                
                            
                        } else if (id instanceof OpenPGPKeyIDKeyIdentifier) {
                            // Searching using keyID
                            
                            if (compareByteArrays(k.getKeyID(), id.getDefaultID())) {
                                // i have finally found what i'm looking for...
                                
                                numDeleted ++;
                                
                                if (isSubKey(p)) {
                                    // this is a subkey
                                    do {
                                        p = in.readPacket();
                                    } while ( (p!=null) && ( !(p instanceof KeyPacket)));
                                        
                                } else {
                                    // this is a primary key
                                    do {
                                        p = in.readPacket();
                                        if ((p!=null) && (isSubKey(p))) {
                                            numDeleted++;
                                        }
                                    } while ((p!=null) && ( (!(p instanceof KeyPacket)) || (isSubKey(p))));
                                }

                                // if not null then we have the next key, write it out
                                if (p!=null) out.writePacket(p);

                            } else {
                                // not what we're looking for. just write
                                out.writePacket(p);
                            }

                        } else {
                            throw new KeyHandlerException("Unrecognised key identifier given");
                        }
                    } else {
                        out.writePacket(p);
                    }
                }
            } while (p!=null);  

            in.close();
            out.close();
            
            // we got here, everything should be ok, so copy modified file back over original
            
            if (numDeleted > 0) {
                if ((!keyring.delete()) || (!tmp.renameTo(keyring)))
                    throw new KeyHandlerException("Failed to create modified keyring!");
            }
           
        
        } catch (Exception e) {
            throw new KeyHandlerException(e.getMessage());
        }
        
        return numDeleted;
    }
    
    /**
     * <p>Look for a key.</p>
     * <p>Looks for a key in the key store as specified by the key identifier.</p>
     * <p>The actual KeyIdentifier class used depends on the type of key being looked for.</p>
     * <p>If you specify a key with a specific key ID, then only that key will be returned. If you specify a key with a user name
     * then the primary key and all sub keys will be returned.</p>
     * <p>If you are looking for a secret key you MUST pass the passphrase in a OpenPGPFindKeyParameters object in order for the secret
     * key data to be decrypted. IMPORTANT : Currently assumes that subkeys are encrypted with the same key, if this is not the case you should
     * seek for each subkey individually by keyID.</p>
     * <p>If you use a OpenPGPKeyIDKeyIdentifier to specify key you may use an 8 byte array of zeros to specify a wildcard. If this is the case, all keys in the keyring will be returned.</p>
     * @param id The key identifier that specifies the key being looked for.
     * @param parameters Any extra parameters needed, for example pass phrases for secret key stores etc, may be null.
     * @return An array of OpenPGPKeyData objects that contain (among other things) the key material and raw key packet, or NULL if no keys matching id could be found.
     * @throws ChecksumFailureException If the key data fails a checksum (usually because the wrong passphrase was supplied).
     * @throws KeyHandlerException if something went wrong.
     */ 
    public KeyObject[] findKeys(KeyIdentifier id, KeyHandlerParameters parameters) throws ChecksumFailureException, KeyHandlerException {
        try {
            
            // create a new file if file does not already exist.
            try {
                File f = new File(getFileName());
                f.createNewFile();
            } catch (IOException e) {
                throw e;
            }
            
            return findKeys(new FileInputStream(getFileName()), id, parameters);
        } catch (ChecksumFailureException c) {
            throw c;
        } catch (KeyHandlerException k) {
            throw k;
        } catch (Exception e) {
            throw new KeyHandlerException(e.getMessage());
        }
    }
    
    /**
     * <p>A quick method used by findKeys to simplify the reading of data from other sources.</p>
     */
    public KeyObject [] findKeys(InputStream stream, KeyIdentifier id, KeyHandlerParameters parameters) throws ChecksumFailureException, KeyHandlerException {
        
        // TODO : Verify signatures and report invalid ones

        Vector keys = new Vector();
        
        Packet p = null;
        UserIDPacket uidPacket = null;
          
        OpenPGPPacketInputStream in = null;
        
        try {
            in = new OpenPGPPacketInputStream(stream);

            do {
                p = in.readPacket();
                
                if (p != null) {
                    // analyse packet
                    
                    // we have encountered a user ID packet, we need to store it so that we can generate a more friendly password fail error
                    if (p instanceof UserIDPacket) 
                        uidPacket = (UserIDPacket)p;
                    
                    // this is a key packet
                    if (p instanceof KeyPacket) { 
                        // this is a key
                        
                        KeyPacket k = (KeyPacket)p;
                        
                        // do i need parameters?
                        if ((p instanceof SecretKeyPacket) && ((parameters == null) || (!(parameters instanceof OpenPGPFindKeyParameters))))
                            throw new KeyHandlerException("Parameters needed to decrypt secret key data");
                        
                        
                        // how are we searching for key?
                        if (id instanceof OpenPGPStandardKeyIdentifier) {
                            // Searching using standard "user <address@example.com>"

                            if (!isSubKey(p)) {
                                // this is a primary key so look for uid and collect subkeys
                                
                                // skip packets until i get to a user ID packet
                                do {
                                    p = in.readPacket();
                                    
                                    if (p == null) throw new KeyHandlerException("Invalid keyring");
                                } while (!(p instanceof UserIDPacket));
                                
                                UserIDPacket uid = (UserIDPacket)p;
                                uidPacket = uid;
                                
                                // is this the key we were looking for?
                                if (compareByteArrays(uid.getID(), id.getDefaultID())) {
                                    // it is 
                                    
                                    // is it a secret key (attempt to decrypt it if it is)
                                    if (k instanceof SecretKeyPacket) {
                                        OpenPGPFindKeyParameters fkp = (OpenPGPFindKeyParameters)parameters;
                                        SecretKeyPacket skp = (SecretKeyPacket)k;
                                        skp.decryptKeyData(fkp.getPassPhrase());
                                    }
                                    
                                    // add primary key 
                                    keys.add(new OpenPGPKeyData(k));
                                    
                                    // add any subkeys
                                    do {
                                        p = in.readPacket();
                                    
                                        // is this a subkey, if so add it
                                        if ((p != null) && (isSubKey(p))) {
                                            
                                            // is it a secret key (attempt to decrypt it if it is)
                                            if (p instanceof SecretKeyPacket) {
                                                OpenPGPFindKeyParameters fkp = (OpenPGPFindKeyParameters)parameters;
                                                SecretKeyPacket skp = (SecretKeyPacket)p;
                                                skp.decryptKeyData(fkp.getPassPhrase());
                                            }

                                            k = (KeyPacket)p;
                                            
                                            // add subkey
                                            keys.add(new OpenPGPKeyData(k));

                                        }
                                    } while ((p!=null) && ( (!(p instanceof KeyPacket)) || (isSubKey(p))));
                                }
                            }
                                
                            // look for uid next, if not found fail.
                        } else if (id instanceof OpenPGPKeyIDKeyIdentifier) {
                            // Searching using keyID, if key is a wildcard or is the one we're looking for, add it
                            byte wildcard[] = {0,0,0,0,0,0,0,0}; 

                            if ((compareByteArrays(k.getKeyID(), id.getDefaultID())) || (compareByteArrays(id.getDefaultID(), wildcard))) {
                                // i have finally found what i'm looking for...

                                // test to see if this is a primary key packet, if it is we need to read user id packet
                                if ( ((k instanceof SecretKeyPacket) && (!(k instanceof SecretSubkeyPacket)) ) || 
                                    ( (k instanceof PublicKeyPacket) && (!(k instanceof PublicSubkeyPacket)) ) ) {
                                        // skip packets until i get to a user ID packet
                                        do {
                                            p = in.readPacket();

                                            if (p == null) throw new KeyHandlerException("Invalid keyring");
                                        } while (!(p instanceof UserIDPacket));

                                        uidPacket = (UserIDPacket)p;
                                }
                                
  
                                // is it a secret key (attempt to decrypt it if it is)
                                if (k instanceof SecretKeyPacket) {
                                    OpenPGPFindKeyParameters fkp = (OpenPGPFindKeyParameters)parameters;
                                    SecretKeyPacket skp = (SecretKeyPacket)k;
                                    skp.decryptKeyData(fkp.getPassPhrase());
                                }
                                
                                // add key                                
                                keys.add(new OpenPGPKeyData(k));
                            }
                        } else {
                            throw new KeyHandlerException("Unrecognised key identifier given");
                        }
                    }
                }
            } while (p!=null);
            
            in.close();
            
        } catch (ChecksumFailureException chksme) {
            // make ChecksumFailureException show a more friendly error message
            throw new ChecksumFailureException("Passphrase needed for key \"" + new String(uidPacket.getID()) +"\"");
        } catch (Exception e) {
            throw new KeyHandlerException(e.getMessage());
        }
        
        // return keys (or null if no keys found)
        if (keys.size()>0) {
            KeyData keydata[] = new KeyData[keys.size()];
            for (int n = 0; n < keydata.length; n++) {
                keydata[n] = (OpenPGPKeyData)keys.get(n);
            }
        
            return keydata;    
        } 
        
        return null;
    }

/* Common utility methods ************************************************************/
    
    /** 
     * <p>Quick test to see if a given pgp key packet is a subkey or not.</p>
     * @return true if packet is either a PublicSubkeyPacket or SecretSubkeyPacket, false otherwise.
     */
    public static boolean isSubKey(Packet packet) {
        if ((packet instanceof PublicSubkeyPacket) || (packet instanceof SecretSubkeyPacket))
            return true;
        else
            return false;
    }
    
    /** 
     * <p>A quick method to compare two byte arrays.</p>
     * @return true if the two byte arrays match, false if not.
     */
    public static boolean compareByteArrays(byte[] one, byte[] two) {
        if (one.length != two.length)
            return false;
        
        for (int n = 0; n < one.length; n++) 
            if (one[n]!=two[n]) 
                return false;
        
        return true;
    }
    
    /** 
     * <p>A quick method to generate the hash data for primary key signatures.</p>
     * @param id The user ID.
     * @param primaryKeyBody The encoded form of the primary key key packet body.
     */
    protected byte[] generatePrimaryKeyHashData(OpenPGPStandardKeyIdentifier id, byte[] primaryKeyBody) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
      
        out.write(0x99);
        out.write((primaryKeyBody.length >> 8) & 0xff);
        out.write(primaryKeyBody.length & 0xff);
        out.write(primaryKeyBody);

        out.write(0xb4);
        out.write((id.getDefaultID().length >> 24) & 0xff);
        out.write((id.getDefaultID().length >> 16) & 0xff);
        out.write((id.getDefaultID().length >> 8) & 0xff);
        out.write(id.getDefaultID().length & 0xff);
        out.write(id.getDefaultID());
        
        return out.toByteArray();
    }
    
    /** 
     * <p>A quick method to generate the hash data for subkey signatures.</p>
     * @param primaryKeyBody The encoded form of the primary key key packet body.
     * @param subKeyBody The encoded form of the subkey key packet body.
     */
    protected byte[] generateSubKeyHashData(byte[] primaryKeyBody, byte[] subKeyBody) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        
        out.write(0x99);
        out.write((primaryKeyBody.length >> 8) & 0xff);
        out.write(primaryKeyBody.length & 0xff);
        out.write(primaryKeyBody);

        out.write(0x99);
        out.write((subKeyBody.length >> 8) & 0xff);
        out.write(subKeyBody.length & 0xff);
        out.write(subKeyBody);
        
        return out.toByteArray();
    }
    
    /** 
     * <p>A quick method to generate a 0x10 type V4 signature over a primary key.</p>
     * @param key The signing key.
     * @param keyID[] The signing key's ID
     * @param param Parameters for the key.
     * @param hashData[] The data to hash.
     */
    protected V4SignatureMaterial generatePrimarySignature(PrivateKey key, byte keyID[], OpenPGPAddKeyParameters param, byte [] hashData) throws Exception {
        
        // generate signature material
        V4SignatureMaterial sigMaterial = new V4SignatureMaterial(
            key, // private key to sign with
            0, // expiry
            keyID, // the key ID
            0x10, // signature type (generic certification of a user ID and public key packet)
            param.getPublicKeyAlgorithm(), // key algorithm
            2, // hash algorithm (SHA1)
            hashData
        );

        // this is a primary user id
        sigMaterial.addHashedSubPacket(new PrimaryUserIDSubPacket(true));

        // set key flags
        KeyFlagsSubPacket kf = new KeyFlagsSubPacket(1);
        kf.setMaySignDataFlag(true);
        kf.setMayCertifyKeyFlag(true);
        sigMaterial.addHashedSubPacket(kf);

        // algorithm prefs
        if (param.getSymmetricAlgorithmPrefs()!=null)
            sigMaterial.addHashedSubPacket(new PreferredSymmetricAlgorithmSubPacket(param.getSymmetricAlgorithmPrefs()));

        if (param.getHashAlgorithmPrefs() != null)
        	sigMaterial.addHashedSubPacket(new PreferredHashAlgorithmSubPacket(param.getHashAlgorithmPrefs()));
        
        if (param.getCompressionAlgorithmPrefs() != null)
        	sigMaterial.addHashedSubPacket(new PreferredCompressionAlgorithmSubPacket(param.getCompressionAlgorithmPrefs()));
        	
        // re-sign data
        sigMaterial.sign(key, hashData);
        
        return sigMaterial;
    }
    
    /** 
     * <p>A quick method to generate a 0x18 type V4 signature over a subkey.</p>
     * @param key The signing key.
     * @param keyID[] The signing key's ID
     * @param param Parameters for the key.
     * @param hashData[] The data to hash.
     */
    protected V4SignatureMaterial generateSubkeySignature(PrivateKey key, byte keyID[], OpenPGPAddKeyParameters param, byte [] hashData) throws Exception {
    	// generate signature material
        V4SignatureMaterial sigMaterial = new V4SignatureMaterial(
            key, // private key to sign with
            0, // expiry
            keyID, // key ID of signing key
            0x18, // signature type (subkey binding signature)
            param.getSigningKeyAlgorithm(), // signing key algorithm
            2, // hash algorithm (SHA1)
            hashData
        );

        // set key flags
        KeyFlagsSubPacket kf = new KeyFlagsSubPacket(1);
        kf.setMayEncryptCommsFlag(true);
        kf.setMayEncryptStorageFlag(true);
        sigMaterial.addHashedSubPacket(kf);

        // resign data
        sigMaterial.sign(key, hashData);
        
        return sigMaterial;
    }
    
    /** 
     * A quick method to generate an itterated and salted S2K object for generating secret key packets.
     */
    protected S2K createS2K(int hashAlgorithm) throws Exception {
        byte salt[] = new byte[8];

        SecureRandom rng = SecureRandom.getInstance("SHA1PRNG");
        rng.nextBytes(salt);
        
        return new S2K(hashAlgorithm, salt);
    }

}
