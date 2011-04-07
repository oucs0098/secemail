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
import core.algorithmhandlers.keymaterial.*;
import core.algorithmhandlers.openpgp.util.*;
import org.bouncycastle.jce.provider.*;
import java.util.*;
import java.io.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.math.BigInteger;

/**
 * <p>Implements a V3 Signature packet.</p>
 */
public class V3SignatureMaterial extends SignatureMaterial {
    
    /** When the key was signed */
    private long signedTime;
    
    /** Key id */
    private byte keyID[];
    
    /** Create a new instance of V3SignatureMaterial suitable for construction with the build method.*/
    public V3SignatureMaterial() {
    }
    
    /** <p>Creates a new instance of V3SignatureMaterial.</p>
     * @param key The private key to sign the packet with.
     * @param keyID[] The 8 byte key id of the signing key (as calculated by the appropriate AsymmetricAlgorithmParameters method).
     * @param sigType The type of signature this is.
     * @param keyalgorithm The type of public key algorithm to use.
     * @param hashalgorithm The type of hash algorithm to use.
     * @param data[] The data to sign (the encoded packet data).
     * @throws AlgorithmException if signature could not be created for whatever reason.
     */
    public V3SignatureMaterial(PrivateKey key, byte keyID[], int sigType, int keyalgorithm, int hashalgorithm, byte data[]) throws AlgorithmException {
        setSignatureType(sigType);
        setCreateDate(new Date().getTime() / 1000);
        setPublicKeyAlgorithm(keyalgorithm);
        setHashAlgorithm(hashalgorithm);
        
        setKeyID(keyID); 
        
        sign(key, data); // sign and generate hash
    }
    
    /** Set the creation date of the key */
    protected void setCreateDate(long date) {
        signedTime = date;
    }
    
    /** Get the creation date of the key */
    public long getCreateDate() {
        return signedTime;
    }
 
    /**
     * <p>Retrieve the key ID data.</p>
     * <p>Key IDs are stored in a slightly different way depending on the version of the packet.
     * With V4 keys it is possible (although unlikely) that there is no key ID stored.</p>
     * @throws AlgorithmException if the key id could not be retrieved for whatever reason.
     */
    public byte[] getKeyID() throws AlgorithmException {
        return keyID;
    }
    
    /**
     * <p>Set the key ID.</p>
     * @throws AlgorithmException if the key id could not be set for whatever reason.
     */
    protected void setKeyID(byte[] id) throws AlgorithmException {
        keyID = id;
    }

    /**
     * <p>Construct the signature material out of an input stream.</p>
     * @throws AlgorithmException if something goes wrong.
     */
    public void build(InputStream in) throws AlgorithmException {
        try {
            // check length byte
            if (in.read()!=5) throw new AlgorithmException("Badly formed v3 signature material, length octet is not 5");
            
                // read signature type
                setSignatureType(in.read());

                // read date 
                long date = ( ((in.read() & 0xFFl) << 24) 
                    | ((in.read() & 0xFFl) << 16)
                    | ((in.read() & 0xFFl) <<  8)
                    | ((in.read() & 0xFFl) ));
                setCreateDate(date);
                
            // read key id
            keyID = new byte[8];
            in.read(keyID);

            // public key algorithm
            setPublicKeyAlgorithm(in.read());
            
            // hash algorithm
            setHashAlgorithm(in.read());
            
            // hash
            setHash(((in.read() & 0xFF ) << 8) | (in.read() & 0xFF));
            
            // encoded signature data
            byte sigdata[] = new byte[in.available()];
            in.read(sigdata);
            setSignature(sigdata);
            
        } catch (Exception e) {
            throw new AlgorithmException(e.getMessage());
        }
    }    
    
    /**
     * <p>Encode the signature material and return it as a byte array.</p>
     * @throws AlgorithmException if something goes wrong.
     */
    public byte[] encode() throws AlgorithmException {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            
            out.write(5 & 0xff);
                out.write(getSignatureType() & 0xff);
                
                out.write((int)((getCreateDate() >> 24) & 0xFF));
                out.write((int)((getCreateDate() >> 16) & 0xFF));
                out.write((int)((getCreateDate() >> 8) & 0xFF));
                out.write((int)((getCreateDate() >> 0) & 0xFF));
                
            
            out.write(getKeyID());
            
            out.write(getPublicKeyAlgorithm() & 0xff);
            
            out.write(getHashAlgorithm() & 0xff);
            
            out.write((getHash() >> 8) & 0xff);
            out.write(getHash() & 0xff);
  
            out.write(getSignature());
            
            return out.toByteArray();
            
        } catch (Exception e) {
            throw new AlgorithmException(e.getMessage());
        }
    }
 
    /**
     * <p>A utility method used to construct the raw data used in the signature algorithm.</p>
     * @param data[] The initial data used in the calculation, i.e. the data you're signing.
     * @return a byte array containing the raw signature data.
     * @throws AlgorithmException if something went wrong.
     */
    protected byte[] calculateRawSigData(byte[] data) throws AlgorithmException {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            
            // initial data
            out.write(data);
            
            // signature type
            out.write(getSignatureType() & 0xFF);
            
            // date
            out.write((int)((getCreateDate() >> 24) & 0xFF));
            out.write((int)((getCreateDate() >> 16) & 0xFF));
            out.write((int)((getCreateDate() >> 8) & 0xFF));
            out.write((int)((getCreateDate() >> 0) & 0xFF));
            
            return out.toByteArray();
        } catch (IOException e) {
            throw new AlgorithmException(e.getMessage());
        }
    }
    
}
