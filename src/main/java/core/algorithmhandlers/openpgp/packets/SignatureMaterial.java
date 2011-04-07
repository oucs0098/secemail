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
import java.io.*;
import java.security.*;
import java.math.BigInteger;

/**
 * <p>Abstract root class for all signature material packets.</p>
 */
public abstract class SignatureMaterial {

    /** Signature type */
    private int signatureType;
    
    /** Public key algorithm used */
    private int publicKeyAlgorithm;
    
    /** Hash algorithm used */
    private int hashAlgorithm;
    
    
    /** 2byte hash data (left 16 bits of signature) */
    private int hash;   
    /** Signature material */
    private byte[] signature;

    
    /** Creates a new instance of SignatureMaterial */
    public SignatureMaterial() {
    }
    
    /** Set the signature type. */
    protected void setSignatureType(int type) {
        signatureType = type;
    }
    
    /** Get the signature type. */
    public int getSignatureType() {
        return signatureType;
    }
    
    /** Get the public key algorithm */
    public int getPublicKeyAlgorithm() {
        return publicKeyAlgorithm;
    }
    
    /** Set the public key algorithm */
    protected void setPublicKeyAlgorithm(int algorithm) {
        publicKeyAlgorithm = algorithm;
    }
    
    /** Get the hash algorithm */
    public int getHashAlgorithm() {
        return hashAlgorithm;
    }
    
    /** Set the hash algorithm */
    protected void setHashAlgorithm(int algorithm) {
        hashAlgorithm = algorithm;
    }
    
    /** <p>Get the 2 byte hash. </p>
     * <p>This is calculated when a sub packet is created.</p>
     */
    public int getHash() {
        return hash;
    }
    
    /** <p>Set the 2 byte hash. </p>
     * <p>This is calculated when a sub packet is created.</p>
     */
    protected void setHash(int twoByteHash) {        
        hash = twoByteHash;
    }
    
    /**
     * <p>Return the raw signature material.</p>
     */
    public byte[] getSignature() {
        return signature;
    }
    
    /**
     * <p>Set the raw signature material.</p>
     * <p>This material is a raw byte representation of the encoded MPIs representing the algorithm
     * specific signature material.</p>
     */
    protected void setSignature(byte[] sig) {
        signature = sig;
    }
    
    /** 
     * <p>Retrieve the key ID data.</p>
     * <p>Key IDs are stored in a slightly different way depending on the version of the packet. 
     * With V4 keys it is possible (although unlikely) that there is no key ID stored.</p>
     * @throws AlgorithmException if the key id could not be retrieved for whatever reason.
     */
    public abstract byte[] getKeyID() throws AlgorithmException;
    
    /**
     * <p>Set the key ID.</p>
     * <p>This is done in a different way depending on the version of the packet, eg v4 signatures
     * store this information as a sub packet.</p>
     * @throws AlgorithmException if the key id could not be set for whatever reason.
     */
    protected abstract void setKeyID(byte [] id) throws AlgorithmException;
    
    /** 
     * <p>Generate a signature.</p>
     * <p>This method generates a signature using the previously registered key and
     * hash algorithm. </p>
     * <p>The method will also generate the hash and key id where appropriate.</p>
     * @param key The key to use to sign the data.
     * @param data[] The data to sign.
     * @throws AlgorithmException if something went wrong.
     */
    public void sign(PrivateKey key, byte data[]) throws AlgorithmException {
        try {
            // generate hash message digest
            MessageDigest md = MessageDigest.getInstance(HashAlgorithmSettings.getHashText(getHashAlgorithm()), "BC");
            
            // init for signing
            Signature signature = Signature.getInstance(HashAlgorithmSettings.getHashText(getHashAlgorithm()) + 
                    PublicKeyAlgorithmSettings.getSignatureAlgorithmTailText(getPublicKeyAlgorithm()), "BC");
            
            signature.initSign(key);
            
            // create signature & generate hash
            md.update(calculateRawSigData(data));
            signature.update(calculateRawSigData(data));
            byte digest[] = md.digest();
            byte sig[] = signature.sign();
            
            // set hash
            setHash(((digest[0] & 0xFF ) << 8) | (digest[1] & 0xFF));
            
            // set signature
            if (PublicKeyAlgorithmSettings.isRSA(getPublicKeyAlgorithm())) {
                setSignature(MPI.toByteArray(new BigInteger(1, sig)));
            } else if (PublicKeyAlgorithmSettings.isDSA(getPublicKeyAlgorithm())) {
            	setSignature(parseDSAData(sig));
            } else {
                throw new AlgorithmException("Unsupported signature algorithm.");
            }
            
        } catch (Exception e) {
            throw new AlgorithmException(e.getMessage());
        }
    }
    
    /**
     * <p>Verify the signature material against the signer's public key.</p>
     * @param signersKey The public key belonging to the signer of the packet.
     * @param data[] The data to verify against.
     * @return true if the signature is valid, false if not.
     * @throws AlgorithmException if something went wrong.
     */
    public boolean verify(PublicKey signersKey, byte[] data) throws AlgorithmException {
        try {
            // init signature for verification
            Signature signature = Signature.getInstance(HashAlgorithmSettings.getHashText(getHashAlgorithm()) + 
            			PublicKeyAlgorithmSettings.getSignatureAlgorithmTailText(getPublicKeyAlgorithm()), "BC");
            signature.initVerify(signersKey);
            
            // load signature object with the data to compare against
            signature.update(calculateRawSigData(data));

            // verify the signature
            if (PublicKeyAlgorithmSettings.isRSA(getPublicKeyAlgorithm())) {
                return signature.verify(MPI.getBytes(getSignature()));
            } else if (PublicKeyAlgorithmSettings.isDSA(getPublicKeyAlgorithm())) {
                
                ByteArrayInputStream in = new ByteArrayInputStream(getSignature());
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                
                byte[] oneBytes = MPI.valueOf(in).toByteArray();
                byte[] twoBytes = MPI.valueOf(in).toByteArray();
                
                out.write(0x30);
                out.write((oneBytes.length + twoBytes.length + 4));
                
                out.write(0x02);
                out.write(oneBytes.length);
                out.write(oneBytes);
                
                out.write(0x02);
                out.write(twoBytes.length); 
                out.write(twoBytes);
                
                return signature.verify(out.toByteArray());
            } else {
                throw new AlgorithmException("Unsupported signature algorithm.");
            }
            
        } catch (Exception e) {
            throw new AlgorithmException(e.getMessage());
        }
    }
    
    /**
     * Parse the result of DSA calculation into its encoded form.
     */
    private byte [] parseDSAData(byte [] data) throws IOException, AlgorithmException {       
        ByteArrayInputStream in = new ByteArrayInputStream(data);

        if (((in.read() & 0xff) != 0x30) || ((in.read() & 0xff) != data.length-2) || ((in.read() & 0xff) != 0x02))
            throw new AlgorithmException("Signature is invalid.");

        byte length = (byte)(in.read() & 0xff);

        if (length > 21)
            throw new AlgorithmException("Signature is invalid.");

        byte[] r = new byte[length];
        in.read(r);

        if ((in.read() & 0xff) != 0x02)
            throw new AlgorithmException("Signature is invalid.");

        length = (byte)(in.read() & 0xff);

        if (length > 21)
            throw new AlgorithmException("Signature is invalid.");

        byte[] s = new byte[length];
        in.read(s);       
        
        if (in.available()>0)
            throw new AlgorithmException("Signature is invalid.");
        
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(MPI.toByteArray(r));
        out.write(MPI.toByteArray(s));
        
        return out.toByteArray();
    }
    
    /**
     * <p>Construct the signature material out of an input stream.</p>
     * @throws AlgorithmException if something goes wrong.
     */
    public abstract void build(InputStream in) throws AlgorithmException;
    
    /**
     * <p>Encode the signature material and return it as a byte array.</p>
     * @throws AlgorithmException if something goes wrong. 
     */
    public abstract byte[] encode() throws AlgorithmException;  

    /**
     * <p>A utility method used to construct the raw data used in the signature algorithm.</p>
     * @param data[] The initial data used in the calculation, i.e. the data you're signing.
     * @return a byte array containing the raw signature data.
     * @throws AlgorithmException if something went wrong.
     */
    protected abstract byte[] calculateRawSigData(byte[] data) throws AlgorithmException;
    
}
