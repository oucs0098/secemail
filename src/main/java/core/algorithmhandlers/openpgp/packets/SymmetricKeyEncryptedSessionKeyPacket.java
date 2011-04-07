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

package core.algorithmhandlers.openpgp.packets;
import core.exceptions.AlgorithmException;
import core.algorithmhandlers.openpgp.util.*;
import org.bouncycastle.jce.provider.*;
import java.math.BigInteger;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;

/**
 * <p>A class representing a symmetric key encrypted session packet.</p>
 */
public class SymmetricKeyEncryptedSessionKeyPacket extends EncryptedSessionKeyPacket {
    
    /** S2K Specifier used to generate keys.*/
    private S2K s2kSpecifier;

    
    /** Creates a new instance of SymmetricKeyEncryptedSessionKeyPacket with no header */
    public SymmetricKeyEncryptedSessionKeyPacket() {
    }
    
    /**
     * A more useful constructor. Automatically creates header. 
     * @param passPhrase[] The pass phrase to use to encrypt the session key.
     * @param algorithm The symmetric key algorithm to use to encrypt the session key with.
     * @param s2k The s2k specifier to use.
     * @param sessionkey The unencrypted session key that will be packed in this object.
     * @throws AlgorithmException if the packet could not be created.
     */
    public SymmetricKeyEncryptedSessionKeyPacket(byte passPhrase[], int algorithm, S2K s2k, SessionKey sessionkey) throws AlgorithmException {
        setVersion(4);
        setKeyAlgorithm(algorithm);
        setS2K(s2k);
        setSessionKey(passPhrase, sessionkey);
        setPacketHeader(new PacketHeader(3, false, 2 + s2k.toByteArray().length + encryptedSessionKey.length));
    }
    
    /**
     * <p>A more useful constructor. Automatically creates header. </p>
     * <p>This constructor uses the s2k specifier and passphrase to generate a key which can be used to encrypt following data packets.</p>
     * <p>Packets created with this constructor will NOT write the session key out.</p>
     * @param algorithm The symmetric algorithm used to encrypt the following data packet (when using this constructor no encrypted session key is stored).
     * @param s2k The s2k specifier to use.
     * @throws AlgorithmException if the packet could not be created.
     */
    public SymmetricKeyEncryptedSessionKeyPacket(int algorithm, S2K s2k) throws AlgorithmException {
        setVersion(4);
        setKeyAlgorithm(algorithm);
        setS2K(s2k);
        encryptedSessionKey = null; // there is no session key being stored
        setPacketHeader(new PacketHeader(3, false, 2 + s2k.toByteArray().length));
    }
    
    /** Set the s2k specifier to use to generate keys. */
    protected void setS2K(S2K s2k) {
        s2kSpecifier = s2k;
    }
    
    /** Returns the previously set s2k specifier. */
    public S2K getS2K() {
        return s2kSpecifier;
    }
    
    /**
     * <p>A method constructs a packet out of raw binary data.</p>
     * <p>You should implement this in all your packets. If a packet is a container packet
     * you must also populate the subpackets vector by extracting and constructing the relevent packets.</p>
     * @param data[] The packet body data as a raw binary bytestream. If you are using OpenPGPPacketInputStream the header will automatically be created for you.
     * @throws AlgorithmException if there was a problem.
     */
    public void buildPacket(byte[] data) throws AlgorithmException {
        // check for session key, if there then load
        
        try {
            ByteArrayInputStream in = new ByteArrayInputStream(data);
            
            setVersion(in.read() & 0xFF);
             
            setKeyAlgorithm(in.read() & 0xFF);
            
            setS2K(new S2K(in));
            
            // rest of the data (if there)
            if (in.available()>0) {
                encryptedSessionKey = new byte[in.available()];
                in.read(encryptedSessionKey);
            }
            
        } catch (IOException e) {
            throw new AlgorithmException(e.getMessage());
        }
    }
    
    /**
     * <p>A method that produces a straight binary representation of this packet.</p>
     * <p>You should override this as necessary.</p>
     * <p>You should also encode the header as part of this method by calling the header object's
     * encodeHeader method.</p>
     * @throws AlgorithmException if there was a problem.
     */
    public byte[] encodePacket() throws AlgorithmException {
        
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            
            out.write(getPacketHeader().encodeHeader());
            
            out.write(encodePacketBody());
            
            return out.toByteArray();
            
        } catch (IOException e) {
            throw new AlgorithmException(e.getMessage());
        }
        
    }
    
    
    /**
     * <p>A method that produces a straight binary representation of this packet's BODY.</p>
     * <p>You should override this as necessary.</p>
     * @throws AlgorithmException if there was a problem.
     */
    public byte[] encodePacketBody() throws AlgorithmException {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            
            out.write(getVersion() & 0xFF);         
            out.write(getKeyAlgorithm() & 0xFF);
            out.write(getS2K().toByteArray());
            
            // write session key if necessary
            if (encryptedSessionKey!=null)
                out.write(encryptedSessionKey);
            
            return out.toByteArray();
            
        } catch (IOException e) {
            throw new AlgorithmException(e.getMessage());
        }
    }
    
    /**
     * <p>Unpack and decrypt the saved session key using the given key and return the
     * session key in its clear form.</p>
     * <p>If the packet does not contain a session key, a session key object of "key" is produced.</p>
     * <p>For this class, use of this interface should be avoided. Use <i>getSessionKey(byte[])</i> instead.</p>
     * @throws AlgorithmException if something went wrong.
     */
    public SessionKey getSessionKey(Key key) throws AlgorithmException {
        // test to make sure its the correct key type
        if (!(key instanceof SecretKey))
            throw new AlgorithmException("Key used for decrypting the session key is not a Secret Key!");
        
        try {
            // if session key is present decrypt and return ELSE return session key of "key" + algorithm
            if (encryptedSessionKey!=null) {
                // decrypt the session key

                // generate all zero iv
                    int blocksize = SymmetricAlgorithmSettings.getDefaultBlockSize(getKeyAlgorithm())/8;
                    byte IV[] = new byte[blocksize];
                    for (int n=0; n<blocksize; n++) IV[n]=0;
                    IvParameterSpec iv = new IvParameterSpec(IV);   
                
                // create cipher
                    Cipher cipher = Cipher.getInstance(SymmetricAlgorithmSettings.getCipherText(getKeyAlgorithm()) 
                                                            + "/PGPCFB/" // use standard CFB mode for this case
                                                            + SymmetricAlgorithmSettings.getPaddingText(getKeyAlgorithm())
                                                            ,"BC");
                    cipher.init(Cipher.DECRYPT_MODE, key, iv);

                // Decrypt data
                    byte decoded[] = cipher.doFinal(encryptedSessionKey);

                // Construct a session key
                    byte sk[] = new byte[decoded.length-1];
                    System.arraycopy(decoded, 1, sk, 0, sk.length);
                    int alg = (int)decoded[0];

                    return new SessionKey(alg, sk);

            } else {
                // create a session key out of key 
                return new SessionKey(getKeyAlgorithm(), key.getEncoded());
            }
        } catch (Exception e) {
            throw new AlgorithmException(e.getMessage());
        }
    }
    
    /**
     * <p>Populate the packet with a given session key.</p>
     * <p>The method will encrypt the given session key data using the given public key and store it.</p>
     * @param key The public key to encrypt the session key to.
     * @param sessionkey The session key data together with the alsogithm.
     * @throws AlgorithmException if something went wrong.
     */
    protected void setSessionKey(Key key, SessionKey sessionkey) throws AlgorithmException {
        // test to make sure its the correct key type
        if (!(key instanceof SecretKey)) 
            throw new AlgorithmException("Key used for encrypting the session key is not a Secret Key!");
        
        try {  
            // generate all zero iv
                int blocksize = SymmetricAlgorithmSettings.getDefaultBlockSize(getKeyAlgorithm())/8;
                byte IV[] = new byte[blocksize];
                for (int n=0; n<blocksize; n++) IV[n]=0;
                IvParameterSpec iv = new IvParameterSpec(IV);   
                   
            // create cipher
                Cipher cipher = Cipher.getInstance(SymmetricAlgorithmSettings.getCipherText(getKeyAlgorithm()) 
                                                            + "/PGPCFB/" // use standard CFB mode for this case
                                                            + SymmetricAlgorithmSettings.getPaddingText(getKeyAlgorithm())
                                                            ,"BC");
                cipher.init(Cipher.ENCRYPT_MODE, key, iv);
  
            // construct session key data
                ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                
                // write algorithm code
                buffer.write(sessionkey.getAlgorithm() & 0xff);

                // write session key data
                buffer.write(sessionkey.getSessionKey());

            // encrypt session key
                encryptedSessionKey = cipher.doFinal(buffer.toByteArray());
                     
        } catch (Exception e) {
            throw new AlgorithmException(e.getMessage());
        }
    }
    
    
    /**
     * <p>Get a session key that can be used to decrypt the following data packet.</p>
     * <p>If this packet contains a session key then that is decrypted using the passPhrase and returned. If
     * the packet DOES NOT contain a session key then a session key is generated FROM passPhrase and returned.</p>
     * <p>You should use this interface instead of <i>getSessionKey(Key)</i>.</p>
     * @throws AlgorithmException if something went wrong.
     */
    public SessionKey getSessionKey(byte passPhrase[]) throws AlgorithmException {
        return getSessionKey(getS2K().generateKey(passPhrase,getKeyAlgorithm()));
    }
 
    /**
     * <p>Set the session key used to encrypt the following data packet, encrypting it using a given pass phrase.</p>
     * @throws AlgorithmException if something went wrong.
     */
    protected void setSessionKey(byte passPhrase[], SessionKey sessionkey) throws AlgorithmException {
        setSessionKey(getS2K().generateKey(passPhrase, getKeyAlgorithm()), sessionkey);
    }

}
