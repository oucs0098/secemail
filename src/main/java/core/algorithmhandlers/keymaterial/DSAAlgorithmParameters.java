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
 * <p>This class acts as a wrapper for the DSA algorithm parameters.</p>
 * <p>This class also provides a convenient way to load and save the parameters in keyring format.</p>
 */
public class DSAAlgorithmParameters extends AsymmetricAlgorithmParameters {
    
    /** Public key components */
    MPI p,
        q,
        g,
        y;
    
    /** Private key components */
    MPI x;
    
    /** Creates a new instance of DSAAlgorithmParameters */
    public DSAAlgorithmParameters() {
        p = null;
        q = null;
        g = null;
        y = null;
    
        x = null;
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
    
    /** Set the value of g. */
    public void setG(BigInteger value) {
        g = new MPI(value);
    }
    
    /** Get the value of g. */
    public BigInteger getG() {
        return g.getValue();
    }
    
    /** Set the value of y. */
    public void setY(BigInteger value) {
        y = new MPI(value);
    }
    
    /** Get the value of y. */
    public BigInteger getY() {
        return y.getValue();
    }
    
    /** Set the value of x. */
    public void setX(BigInteger value) {
        x = new MPI(value);
    }
    
    /** Get the value of x. */
    public BigInteger getX() {
        return x.getValue();
    }
        
    /** <p>Create an algorithm parameter out of encoded secret key component data.</p>
     * @param stream A byte array containing the encoded data for this algorithm according to the OpenPGP spec.
     * @throws AlgorithmException if something went wrong.
     *
     */
    public void decodePrivateKeyComponents(InputStream stream) throws AlgorithmException {
        x = new MPI(stream);
    }
    
    /** <p>Create an algorithm parameter out of encoded public key component data.</p>
     * @param stream A byte stream containing the encoded data for this algorithm according to the OpenPGP spec.
     * @throws AlgorithmException if something went wrong.
     *
     */
    public void decodePublicKeyComponents(InputStream stream) throws AlgorithmException {
        p = new MPI(stream);
        q = new MPI(stream);
        g = new MPI(stream);
        y = new MPI(stream);
    }
    
    /**
     * <p>Produce a encoded version of the algorithms private key components according to the
     * OpenPGP Secret Key Packet format.</p>
     * <p>Encodes the algorithm specific public key MPIs according in the order described in the OpenPGP spec
     * for the specific algorithm.</p>
     * @throws AlgorithmException if something went wrong.
     *
     */
    public byte[] encodePrivateKeyComponents() throws AlgorithmException {
        return x.toByteArray();
    }
    
    /**
     * <p>Produce a encoded version of the algorithms public key components according to the
     * OpenPGP Public Key Packet format.</p>
     * <p>Encodes the algorithm specific public key MPIs according in the order described in the OpenPGP spec
     * for the specific algorithm.</p>
     * @throws AlgorithmException if something went wrong.
     *
     */
    public byte[] encodePublicKeyComponents() throws AlgorithmException {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            
            out.write(p.toByteArray());
            out.write(q.toByteArray());
            out.write(g.toByteArray());
            out.write(y.toByteArray());
            
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
     *
     */
    public void generateKeyPair(int keysize, SecureRandom random) throws AlgorithmException {
        try {
            KeyPairGenerator k = KeyPairGenerator.getInstance("DSA", "BC");
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
     *
     */
    public PrivateKey getPrivateKey() throws AlgorithmException {
        if (x == null)
            throw new AlgorithmException("Not enough key material to construct Private key");
        
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("DSA", "BC");

            DSAPrivateKeySpec privatekeyspec = new DSAPrivateKeySpec(getX(), getP(), getQ(), getG());

            return keyFactory.generatePrivate(privatekeyspec);
          
        } catch (Exception e) {
            throw new AlgorithmException(e.getMessage());
        }
    }
    
    /**
     * <p>Generates a public key using the previously stored parameters.</p>
     * @throws AlgorithmException if the key could not be generated.
     *
     */
    public PublicKey getPublicKey() throws AlgorithmException {
        if ((p == null) || (q == null) || (g == null) || (y == null))
            throw new AlgorithmException("Not enough key material to construct Public key");
        
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("DSA", "BC");

            DSAPublicKeySpec publickeyspec = new DSAPublicKeySpec(getY(), getP(), getQ(), getG());
            
            return keyFactory.generatePublic(publickeyspec);
        } catch (Exception e) {
            throw new AlgorithmException(e.getMessage());
        }
    }
    
    /** <p>Wraps a private key and extracts its parameters.</p>
     * @param key The private key to wrap.
     * @throws AlgorithmException if the key could not be wrapped.
     *
     */
    public void wrapPrivateKey(PrivateKey key) throws AlgorithmException {
        if (!(key instanceof DSAKey)) 
            throw new AlgorithmException("DSAAlgorithmParameters class can not wrap a non DSA key!");
        
        DSAPrivateKey dsa = (DSAPrivateKey)key;
        
        setX(dsa.getX());
    }
    
    /** <p>Wraps a public key and extracts its parameters.</p>
     * @param key The public key to wrap.
     * @throws AlgorithmException if the key could not be wrapped.
     *
     */
    public void wrapPublicKey(PublicKey key) throws AlgorithmException {
        if (!(key instanceof DSAKey)) 
            throw new AlgorithmException("DSAAlgorithmParameters class can not wrap a non DSA key!");

        DSAPublicKey dsa = (DSAPublicKey)key;
        
        setP(dsa.getParams().getP());
        setQ(dsa.getParams().getQ());
        setG(dsa.getParams().getG());
        setY(dsa.getY());       
    }
    
}
