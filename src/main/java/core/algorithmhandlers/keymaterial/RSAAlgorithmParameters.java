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

package core.algorithmhandlers.keymaterial;
import core.exceptions.AlgorithmException;
import core.algorithmhandlers.openpgp.util.MPI;
import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;
import java.math.BigInteger;
import java.io.*;

/**
 * <p>This class acts as a wrapper for the RSA algorithm parameters.</p>
 * <p>This class also provides a convenient way to load and save the parameters in keyring format.</p>
 */
public class RSAAlgorithmParameters extends AsymmetricAlgorithmParameters {
    
    /** Public key components */
    MPI n,
        e;
    
    /** Private key components */
    MPI d,
        p,
        q,
        u;
        
    /** Creates a new instance of RSAParameters */
    public RSAAlgorithmParameters() {
        n = null;
        e = null;
        
        d = null;
        p = null;
        q = null;
        u = null;
    }
    
    /** Set the value of n. */
    public void setN(BigInteger value) {
        n = new MPI(value);
    }
    
    /** Get the value of n. */
    public BigInteger getN() {
        return n.getValue();
    }
    
    /** Set the value of e. */
    public void setE(BigInteger value) {
        e = new MPI(value);
    }
    
    /** Get the value of e. */
    public BigInteger getE() {
        return e.getValue();
    }
    
    /** Set the value of d. */
    public void setD(BigInteger value) {
        d = new MPI(value);
    }
    
    /** Get the value of d. */
    public BigInteger getD() {
        return d.getValue();
    }
    
    /** Set the value of p. */
    public void setP(BigInteger value) {
        p = new MPI(value);
    }
    
    /** Get the value of p. */
    public BigInteger getP() {
        return p.getValue();
    }
    
    /** Set the value of q. */
    public void setQ(BigInteger value) {
        q = new MPI(value);
    }
    
    /** Get the value of q. */
    public BigInteger getQ() {
        return q.getValue();
    }
    
    /** Set the value of u. */
    public void setU(BigInteger value) {
        u = new MPI(value);
    }
    
    /** Get the value of u. */
    public BigInteger getU() {
        return u.getValue();
    }
    
    /**
     * <p>Create an algorithm parameter out of encoded secret key component data.</p>
     * @param stream A byte array containing the encoded data for this algorithm according to the OpenPGP spec.
     * @throws AlgorithmException if something went wrong.
     */
    public void decodePrivateKeyComponents(InputStream stream) throws AlgorithmException {
        d = new MPI(stream);
        p = new MPI(stream);
        q = new MPI(stream);
        u = new MPI(stream);
    }    
    
    /**
     * <p>Create an algorithm parameter out of encoded public key component data.</p>
     * @param stream A byte stream containing the encoded data for this algorithm according to the OpenPGP spec.
     * @throws AlgorithmException if something went wrong.
     */
    public void decodePublicKeyComponents(InputStream stream) throws AlgorithmException {
        n = new MPI(stream);
        e = new MPI(stream);
    }    
    
    /**
     * <p>Produce a encoded version of the algorithms private key components according to the
     * OpenPGP Secret Key Packet format.</p>
     * <p>Encodes the algorithm specific public key MPIs according in the order described in the OpenPGP spec
     * for the specific algorithm.</p>
     * @throws AlgorithmException if something went wrong.
     */
    public byte[] encodePrivateKeyComponents() throws AlgorithmException {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            
            out.write(d.toByteArray());
            out.write(p.toByteArray());
            out.write(q.toByteArray());
            out.write(u.toByteArray());
            
            return out.toByteArray();
            
        } catch (IOException e) {
            throw new AlgorithmException(e.getMessage());
        }
    }
    
    /**
     * <p>Produce a encoded version of the algorithms public key components according to the
     * OpenPGP Public Key Packet format.</p>
     * <p>Encodes the algorithm specific public key MPIs according in the order described in the OpenPGP spec
     * for the specific algorithm.</p>
     * @throws AlgorithmException if something went wrong.
     */
    public byte[] encodePublicKeyComponents() throws AlgorithmException {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            
            out.write(n.toByteArray());
            out.write(e.toByteArray());
            
            return out.toByteArray();
            
        } catch (IOException e) {
            throw new AlgorithmException(e.getMessage());
        }
    }
    
    /** 
     * <p>Generate a new key pair and save its parameters. </p>
     * @param keysize The key size to generate.
     * @param random A random number generator to use to generate the key.
     * @throws AlgorithmException if something went wrong.
     */
    public void generateKeyPair(int keysize, SecureRandom random) throws AlgorithmException {
        try {
            KeyPairGenerator k = KeyPairGenerator.getInstance("RSA", "BC");
            k.initialize(keysize, random);

            KeyPair kp = k.generateKeyPair();

            wrapPublicKey(kp.getPublic());
            wrapPrivateKey(kp.getPrivate());
        } catch (Exception e) {
            throw new AlgorithmException(e.getMessage());
        }
    }
    
    /**
     * <p>Generates a private key using the previously stored parameters.</p>
     * @throws AlgorithmException if the key could not be generated.
     */
    public PrivateKey getPrivateKey() throws AlgorithmException { 
        
        if ((n == null) || (d == null))
            throw new AlgorithmException("Not enough key material to construct Private key");
        
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");

            RSAPrivateKeySpec privatekeyspec = new RSAPrivateKeySpec(getN(), getD());
            /*RSAPrivateCrtKeySpec privatekeyspec = new RSAPrivateCrtKeySpec(
                getN(),
                getE(),
                getD(),
                getP(),
                getQ(),
                getD().mod(getP().subtract(BigInteger.valueOf(0x1))),
                getD().mod(getQ().subtract(BigInteger.valueOf(0x1))),
                getU()
            );*/
            
            return keyFactory.generatePrivate(privatekeyspec);
          
        } catch (Exception e) {
            throw new AlgorithmException(e.getMessage());
        }
    }    
    
    /**
     * <p>Generates a public key using the previously stored parameters.</p>
     * @throws AlgorithmException if the key could not be generated.
     */
    public PublicKey getPublicKey() throws AlgorithmException { 
        
        if ((n == null) || (e == null))
            throw new AlgorithmException("Not enough key material to construct Public key");
        
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");

            RSAPublicKeySpec publickeyspec = new RSAPublicKeySpec(getN(), getE());
            
            return keyFactory.generatePublic(publickeyspec);
        } catch (Exception e) {
            throw new AlgorithmException(e.getMessage());
        }
    }    
    
    /**
     * <p>Wraps a private key and extracts its parameters.</p>
     * @param key The private key to wrap.
     * @throws AlgorithmException if the key could not be wrapped.
     */
    public void wrapPrivateKey(PrivateKey key) throws AlgorithmException {
       
        if (!(key instanceof RSAKey)) 
            throw new AlgorithmException("RSAAlgorithmParameters class can not wrap a non RSA key!");
        
        RSAPrivateCrtKey rsa = (RSAPrivateCrtKey)key;
             
        setD(rsa.getPrivateExponent());
        setP(rsa.getPrimeP());
        setQ(rsa.getPrimeQ());
        setU(rsa.getCrtCoefficient());
    }
    
    /**
     * <p>Wraps a public key and extracts its parameters.</p>
     * @param key The public key to wrap.
     * @throws AlgorithmException if the key could not be wrapped.
     */
    public void wrapPublicKey(PublicKey key) throws AlgorithmException {
        
        if (!(key instanceof RSAKey)) 
            throw new AlgorithmException("RSAAlgorithmParameters class can not wrap a non RSA key!");
        
        RSAPublicKey rsa = (RSAPublicKey)key;
        
        setN(rsa.getModulus());
        setE(rsa.getPublicExponent());
    }    
      
}
