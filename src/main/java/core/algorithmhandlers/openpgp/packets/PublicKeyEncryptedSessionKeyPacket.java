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
import core.exceptions.ChecksumFailureException;
import core.algorithmhandlers.openpgp.util.*;
import org.bouncycastle.jce.provider.*;
import java.math.BigInteger;
import java.security.*;
import javax.crypto.*;
import java.io.*;

/**
 * <p>A class representing a public key encrypted session packet.</p>
 */
public class PublicKeyEncryptedSessionKeyPacket extends EncryptedSessionKeyPacket {
    
    /** Key id of the signing key. */
    private byte keyID[];
    
    /** Creates a new instance of PublicKeyEncryptedSessionKeyPacket with no header */
    public PublicKeyEncryptedSessionKeyPacket() {
    }
    
    /**
     * A more useful constructor. Automatically creates header. 
     * @param key The public key to use to encrypt the session key.
     * @param kID The 8 byte id of the key used. May be 0 if not known.
     * @param algorithm The public key algorithm to use.
     * @param sessionkey The unencrypted session key that will be packed in this object.
     * @throws AlgorithmException if the packet could not be created.
     */
    public PublicKeyEncryptedSessionKeyPacket(PublicKey key, byte kID[], int algorithm, SessionKey sessionkey) throws AlgorithmException {
        setVersion(3);
        setKeyID(kID);
        setKeyAlgorithm(algorithm);
        setSessionKey(key, sessionkey);
        setPacketHeader(new PacketHeader(1, false, 10 + encryptedSessionKey.length));
    }

    /** Set the key id of the key used to sign the message. */
    protected void setKeyID(byte id[]) {
        keyID = id;
    }
    
    /** Get the key id of the key used to sign the message. */
    public byte[] getKeyID() {
        return keyID;
    }

    /** 
     * <p>Populate the packet with a given session key.</p>
     * <p>The method will encrypt the given session key data using the given public key and store it.</p>
     * @param key The public key to encrypt the session key to.
     * @param sessionkey The session key data together with the alsogithm .
     * @throws AlgorithmException if something went wrong.
     */
    protected void setSessionKey(Key key, SessionKey sessionkey) throws AlgorithmException {
         
        // test to make sure its the correct key type
        if (!(key instanceof PublicKey)) 
            throw new AlgorithmException("Key used for encrypting the session key is not a Public Key!");
        
        try {
            
            // create cipher
                Cipher cipher = Cipher.getInstance(PublicKeyAlgorithmSettings.getFullCipherText(getKeyAlgorithm()),"BC");
                cipher.init(Cipher.ENCRYPT_MODE, key);
                
            // construct session key data
                ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                
                // write algorithm code
                buffer.write(sessionkey.getAlgorithm() & 0xff);

                // write session key data
                buffer.write(sessionkey.getSessionKey());
                
                // calculate checksum
                int chksm = Hash.calculatePGPHash(sessionkey.getSessionKey());
                buffer.write((chksm >> 8) & 0xff);
                buffer.write((chksm & 0xff));

            // encrypt session key
                byte encrypted[] = cipher.doFinal(buffer.toByteArray());
                
            // generate and encode MPIs
                if (PublicKeyAlgorithmSettings.isRSA(getKeyAlgorithm())) {
                    encryptedSessionKey = MPI.toByteArray(encrypted);
                    //encryptedSessionKey = MPI.toByteArray(new BigInteger(encrypted));
                    //encryptedSessionKey = MPI.toByteArray(new BigInteger(1, encrypted));
                   
                } else if (PublicKeyAlgorithmSettings.isElGamal(getKeyAlgorithm())) {
                    
                    // test that the encrypted data is valid
                    if (encrypted.length%2!=0)
                        throw new AlgorithmException("Encrypted session key is not valid!");
                    
                    // construct encrypted data
                    ByteArrayOutputStream out = new ByteArrayOutputStream();  
                    byte[] raw = new byte[encrypted.length/2];
                    
                    System.arraycopy(encrypted,0,raw,0,raw.length);
                    out.write(MPI.toByteArray(raw));
                    //out.write(MPI.toByteArray(new BigInteger(raw)));
                    //out.write(MPI.toByteArray(new BigInteger(1, raw)));
                    
                    System.arraycopy(encrypted,encrypted.length/2,raw,0,raw.length);
                    out.write(MPI.toByteArray(raw));
                    //out.write(MPI.toByteArray(new BigInteger(raw))); 
                    //out.write(MPI.toByteArray(new BigInteger(1, raw))); 
                    
                    encryptedSessionKey = out.toByteArray();
                }
                     
        } catch (Exception e) {
            throw new AlgorithmException(e.getMessage());
        }
    }
    
    /** 
     * <p>Unpack and decrypt the saved session key using the given private key and return the 
     * session key in its clear form.</p>
     * @throws ChecksumFailureException if the decoded session key failed the checksum.
     * @throws AlgorithmException if something went wrong.
     */
    public SessionKey getSessionKey(Key key) throws AlgorithmException, ChecksumFailureException {
        
        // test to make sure its the correct key type
        if (!(key instanceof PrivateKey))
            throw new AlgorithmException("Key used for decrypting the session key is not a Private Key!");
        
        try {
            // create cipher
                Cipher cipher = Cipher.getInstance(PublicKeyAlgorithmSettings.getFullCipherText(getKeyAlgorithm()),"BC");
                cipher.init(Cipher.DECRYPT_MODE, key);
                
            // read in MPIs and decode to raw bytes
                ByteArrayInputStream in = new ByteArrayInputStream(encryptedSessionKey);  
                ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                
                int bits = 0; // how many mpis are there?
                if (PublicKeyAlgorithmSettings.isRSA(getKeyAlgorithm())) {
                    bits = 1;
                } else if (PublicKeyAlgorithmSettings.isElGamal(getKeyAlgorithm())) {
                    bits = 2;
                }
            
                for (int n=0; n<bits; n++) {
                    buffer.write(MPI.getBytes(in));
                    //MPI tmp = new MPI(in);
                    //buffer.write(tmp.getValue().toByteArray());
                }
 
            // decrypt
                byte data[] = cipher.doFinal(buffer.toByteArray());
     
            // construct session key and analyse result of checksum
                int alg = (int)data[0];
                byte sk[] = new byte[data.length-3];
                System.arraycopy(data,1,sk,0,sk.length);
                
                int chksm = ((data[data.length-2] << 8) & 0xFF00) + (data[data.length-1] & 0x00FF);
                int sum = Hash.calculatePGPHash(sk);
                
                if (chksm != sum)
                    throw new ChecksumFailureException("Session key is invalid, checksum is incorrect.");
                    //TODO: Use a different exception here so we can try multiple keys to decode the message?
             
                // construct session key
                return new SessionKey(alg, sk);
                
        } catch (ChecksumFailureException c) {
            throw c;
        } catch (Exception e) {
            throw new AlgorithmException(e.getMessage());
        }
    }
    
    /**
     * <p>A method constructs a packet out of raw binary data.</p>
     * <p>You should implement this in all your packets. If a packet is a container packet
     * you must also populate the subpackets vector by extracting and constructing the relevent packets.</p>
     * @throws AlgorithmException if there was a problem.
     */
    public void buildPacket(byte[] data) throws AlgorithmException {
        
        try {
            ByteArrayInputStream in = new ByteArrayInputStream(data);
            
            setVersion(in.read() & 0xFF);
            
            byte id[] = new byte[8];
            in.read(id);
            setKeyID(id);
            
            setKeyAlgorithm(in.read() & 0xFF);
            
            // rest of the data
            encryptedSessionKey = new byte[in.available()];
            in.read(encryptedSessionKey);
            
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
            
            out.write(getKeyID());
             
            out.write(getKeyAlgorithm() & 0xFF);
            out.write(encryptedSessionKey);
            
            return out.toByteArray();
            
        } catch (IOException e) {
            throw new AlgorithmException(e.getMessage());
        }
    }
    
}
