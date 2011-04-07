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
import core.algorithmhandlers.keymaterial.*;
import core.exceptions.AlgorithmException;
import core.algorithmhandlers.openpgp.util.MPI;
import java.security.*;
import java.util.*;
import java.io.*;

/**
 * <p>A class describing a key packet.</p>
 * <p>This is an abstract class that represents the common functionality of all key packet objects.</p>
 * <p>The only real difference between this class and PublicKeyPacket is that its constructors don't create headers. It exists
 * to give PublicKeyPacket and SecretKeyPacket the ability to share common functionality while keeping them seperate.</p>
 */
public abstract class KeyPacket extends Packet {
 
    /** The version type of the packet.*/
    private int version;
    /** When the key was created */
    private long created;
    /** Lifetime of the key in days. V3 only.*/
    private int v3expiry;
    /** Public key algorithm of this key */
    private int algorithm;
    /** Private/Public key data (where appropriate) */
    private AsymmetricAlgorithmParameters keyData;
        
    /** Creates a new instance of KeyPacket. Does not create a header. */
    public KeyPacket() {
    }
    
    /** Create a version 3 packet. Does not create a header. 
     * @param expiry Number of days this key is valid for, 0 for no expiry.
     * @param keyAlgorithm What public key algorithm is being used.
     * @param keyParams The key data as series of MPIs.
     * @throws AlgorithmException if the packet could not be created.
     * @deprecated Use of this constructor can lead to incorrect key IDs being generated when key material is saved in public and secret key rings. 
     */
    public KeyPacket(int expiry, int keyAlgorithm, AsymmetricAlgorithmParameters keyParams) throws AlgorithmException {
        this(new Date(), expiry, keyAlgorithm, keyParams);
        
        /*setVersion(3);
        setCreateDate(new Date().getTime() / 1000); // the packet was created today
        setV3Expiry(expiry);
        setAlgorithm(keyAlgorithm);
        setKeyData(keyParams);*/
    }
    
    /** Create a version 4 packet. Does not create a header. 
     * @param keyAlgorithm What public key algorithm is being used.
     * @param keyParams The key data as series of MPIs.
     * @throws AlgorithmException if the packet could not be created.
     * @deprecated Use of this constructor can lead to incorrect key IDs being generated when key material is saved in public and secret key rings. 
     */
    public KeyPacket(int keyAlgorithm, AsymmetricAlgorithmParameters keyParams) throws AlgorithmException {
        this(0, keyAlgorithm, keyParams);
        setVersion(4);
    }
    
    /** Create a version 3 packet. Does not create a header. 
     * @param creationdate A date object representing the time the packet is created. If you are creating a PGP keyring you should use the same Date object for both the public and secret key packets. This will ensure that both halfs of the keypair have the same key ID.
     * @param expiry Number of days this key is valid for, 0 for no expiry.
     * @param keyAlgorithm What public key algorithm is being used.
     * @param keyParams The key data as series of MPIs.
     * @throws AlgorithmException if the packet could not be created.
     */
    public KeyPacket(Date creationdate, int expiry, int keyAlgorithm, AsymmetricAlgorithmParameters keyParams) throws AlgorithmException {
        setVersion(3);
        setCreateDate(creationdate.getTime() / 1000); // the packet was created today
        setV3Expiry(expiry);
        setAlgorithm(keyAlgorithm);
        setKeyData(keyParams);
    }
    
    /** Create a version 4 packet. Does not create a header. 
     * @param creationdate A date object representing the time the packet is created. If you are creating a PGP keyring you should use the same Date object for both the public and secret key packets. This will ensure that both halfs of the keypair have the same key ID.
     * @param keyAlgorithm What public key algorithm is being used.
     * @param keyParams The key data as series of MPIs.
     * @throws AlgorithmException if the packet could not be created.
     */
    public KeyPacket(Date creationdate, int keyAlgorithm, AsymmetricAlgorithmParameters keyParams) throws AlgorithmException {
        this(creationdate, 0, keyAlgorithm, keyParams);
        setVersion(4);
    }
   
    /** Set the version type of the key. Either 3 or 4.*/
    protected void setVersion(int packetversion) {
        if ((packetversion < 3) || (packetversion > 4))
            packetversion = 4;
        
        version = packetversion;
    }
    
    /** Get the version type of the key.*/
    public int getVersion() {
        return version;
    }
    
    /** Set the creation date of the key */
    protected void setCreateDate(long date) {
        created = date;
    }
    
    /** Get the creation date of the key */
    public long getCreateDate() {
        return created;
    }
    
    /** Set the lifetime of the key in days, 0 for no expiration.
     * Only supported in V3 key packets. 
     */
    protected void setV3Expiry(int expiry) {
        v3expiry = expiry;
    }
    
    /** Get the lifetime of the key in days, 0 for no expiration. 
     * Only supported in V3 key packets. 
     */
    public int getV3Expiry() {
        return v3expiry;
    }
    
    /** Set the public key algorithm used */
    protected void setAlgorithm(int pkAlgorithm) {
        algorithm = pkAlgorithm;
    }
    
    /** Get the public key algorithm used */
    public int getAlgorithm() {
        return algorithm;
    }
    
    /** Set the key data 
     * @throws AlgorithmException if something went wrong.
     */
    protected void setKeyData(AsymmetricAlgorithmParameters data) throws AlgorithmException {
        keyData = data;
    }
    
    /** Get the key data 
     */
    public AsymmetricAlgorithmParameters getKeyData()  {
        return keyData;
    }
    
    /**
     * <p>Calculate the fingerprint from the key material.</p>
     * @throws AlgorithmException if the fingerprint could not be calculated.
     */
    public byte[] getFingerprint() throws AlgorithmException {
        
        try {
            MessageDigest md = null;

            switch (getVersion()) {
                case 3 : 
                    if (!(getKeyData() instanceof RSAAlgorithmParameters))
                        throw new AlgorithmException("Version 3 keys MUST be RSA");
                    else {
                        RSAAlgorithmParameters rsa = (RSAAlgorithmParameters)getKeyData();
                        
                        md = MessageDigest.getInstance("MD5", "BC");
                        
                        byte [] tmp = new MPI(rsa.getN()).toByteArray();
                        byte [] tmp2 = new byte[tmp.length-2];
                        System.arraycopy(tmp, 2, tmp2, 0, tmp2.length);
                        md.update(tmp2);
                        
                        tmp = new MPI(rsa.getE()).toByteArray();
                        tmp2 = new byte[tmp.length-2];
                        System.arraycopy(tmp, 2, tmp2, 0, tmp2.length);
                        md.update(tmp2);
                    }
                    
                    break;
                case 4 : 
                    int length = keyData.encodePublicKeyComponents().length + 6;
                    
                    md = MessageDigest.getInstance("SHA1", "BC");
                    
                    md.update((byte)0x99);
                    md.update((byte)((length >> 8) & 0xff));            // hi length
                    md.update((byte)(length & 0xff));                   // lo length
                    md.update((byte)4);                                 // packet version
                    md.update((byte)((getCreateDate() >> 24) & 0xFF));  // create date
                    md.update((byte)((getCreateDate() >> 16) & 0xFF));  // create date
                    md.update((byte)((getCreateDate() >> 8) & 0xFF));   // create date
                    md.update((byte)((getCreateDate() >> 0) & 0xFF));   // create date
                    md.update((byte)(getAlgorithm() & 0xff));           // algorithm octet
                    md.update(keyData.encodePublicKeyComponents());     // algorithm specific portion
                    break;
                default : throw new AlgorithmException("I don't know how to calculate v"+getVersion()+" fingerprints");
            }
            
            return md.digest();
            
        } catch (Exception e) {
            throw new AlgorithmException(e.getMessage());
        }
    }    
    
    /**
     * <p>Calculate the keyID from the key material.</p>
     * @throws AlgorithmException if the key ID could not be calculated.
     */
    public byte[] getKeyID() throws AlgorithmException {
        byte keyID [] = new byte[8];
        
        switch (getVersion()) {
            case 3 : 
                if (!(getKeyData() instanceof RSAAlgorithmParameters))
                    throw new AlgorithmException("Version 3 keys MUST be RSA");
                else {
                    RSAAlgorithmParameters rsa = (RSAAlgorithmParameters)getKeyData();
                    byte [] rsabytes = rsa.getN().toByteArray();
                    System.arraycopy(rsabytes, rsabytes.length-8, keyID, 0, 8);
                }
                
                break;
            case 4 : 
                byte fingerprint[] = getFingerprint();
                System.arraycopy(fingerprint, fingerprint.length-8, keyID, 0, 8);
                break;
            default : throw new AlgorithmException("I don't know how to calculate v"+getVersion()+" key IDs");
        }
     
        return keyID;
    }
    
    /** Helper method for inheritance purposes. 
     * @throws IOException if there was a problem reading from the stream.
     * @throws AlgorithmException if there was a problem decoding the data.
     */
    protected void buildKeyPacketFromStream(InputStream in) throws IOException, AlgorithmException {
        // read version
        setVersion(in.read());

        // read created date
        long date = ( ((in.read() & 0xFFl) << 24) 
                    | ((in.read() & 0xFFl) << 16)
                    | ((in.read() & 0xFFl) <<  8)
                    | ((in.read() & 0xFFl) ));
        setCreateDate(date);

        // read expiry date if we need to
        if (getVersion()==3) 
            setV3Expiry(((in.read() & 0xFF ) << 8) | (in.read() & 0xFF));

        // read algorithm
        setAlgorithm(in.read());

        // decode key data
        switch (getAlgorithm()) {
            case 1 : 
            case 2 : 
            case 3 : keyData = new RSAAlgorithmParameters(); break;
            case 17 : keyData = new DSAAlgorithmParameters(); break;
            case 16 : keyData = new ElGamalAlgorithmParameters(); break;
            default : throw new AlgorithmException("Requested Public key encryption algorithm not supported.");
        }
        keyData.decodePublicKeyComponents(in);
    }
    
    /**
     * <p>A method constructs a packet out of raw binary data.</p>
     * <p>You should implement this in all your packets. If a packet is a container packet
     * you must also populate the subpackets vector by extracting and constructing the relevent packets.</p>
     * @param data[] The packet body data as a raw binary bytestream. If you are using OpenPGPPacketInputStream the header will automatically be created for you.
     * @throws AlgorithmException if there was a problem.
     */
    public void buildPacket(byte[] data) throws AlgorithmException {
       
        try {
            ByteArrayInputStream in = new ByteArrayInputStream(data);

            buildKeyPacketFromStream(in);
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
            
            // write header
            out.write(getPacketHeader().encodeHeader());
            
            // write body
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
            
            // write version
            out.write(getVersion() & 0xFF);
            
            // write created date
            out.write((int)((getCreateDate() >> 24) & 0xFF));
            out.write((int)((getCreateDate() >> 16) & 0xFF));
            out.write((int)((getCreateDate() >> 8) & 0xFF));
            out.write((int)((getCreateDate() >> 0) & 0xFF));
            
            // write expiry if v3 packet
            if (getVersion()==3) {
                out.write((getV3Expiry() >> 8) & 0xFF);
                out.write(getV3Expiry() & 0xFF);
            }
            
            // write algorithm we're using
            out.write(getAlgorithm() & 0xFF);
            
            // encode algorithm's public key component
            out.write(keyData.encodePublicKeyComponents());
          
            return out.toByteArray();
        } catch (IOException e) {
            throw new AlgorithmException(e.getMessage());
        }
       
    }
}
