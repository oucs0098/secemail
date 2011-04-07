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
import java.io.InputStream;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.SecureRandom;

/**
 * <p>Superclass for all Public Key Algorithm Parameter classes.</p>
 * <p>An algorithm parameter class contains all parameters relating to a given algorithm, usually
 * this consists of a bunch of MPIs.</p>
 * <p>The class also contains methods for converting between raw parameter MPIs and public/private key objects.</p>
 * @see core.algorithmhandlers.openpgp.util.MPI
 */
public abstract class AsymmetricAlgorithmParameters {
    
    /** 
     * <p>Produce a encoded version of the algorithms public key components according to the
     * OpenPGP Public Key Packet format.</p>
     * <p>Encodes the algorithm specific public key MPIs according in the order described in the OpenPGP spec
     * for the specific algorithm.</p>
     * @throws AlgorithmException if something went wrong.
     */
    public abstract byte[] encodePublicKeyComponents() throws AlgorithmException;
    
    /** 
     * <p>Produce a encoded version of the algorithms private key components according to the
     * OpenPGP Secret Key Packet format.</p>
     * <p>Encodes the algorithm specific public key MPIs according in the order described in the OpenPGP spec
     * for the specific algorithm.</p>
     * @throws AlgorithmException if something went wrong.
     */
    public abstract byte[] encodePrivateKeyComponents() throws AlgorithmException;
    
    /**
     * <p>Create an algorithm parameter out of encoded public key component data.</p>
     * @param stream A byte stream containing the encoded data for this algorithm according to the OpenPGP spec.
     * @throws AlgorithmException if something went wrong.
     */
    public abstract void decodePublicKeyComponents(InputStream stream) throws AlgorithmException;
    
    /**
     * <p>Create an algorithm parameter out of encoded secret key component data.</p>
     * @param stream A byte array containing the encoded data for this algorithm according to the OpenPGP spec.
     * @throws AlgorithmException if something went wrong.
     */
    public abstract void decodePrivateKeyComponents(InputStream stream) throws AlgorithmException;
    
    /** 
     * <p>Generate a new key pair and save its parameters. </p>
     * @param keysize The key size to generate.
     * @param random A random number generator to use to generate the key.
     * @throws AlgorithmException if something went wrong.
     */
    public abstract void generateKeyPair(int keysize, SecureRandom random) throws AlgorithmException;
    
    /** 
     * <p>Generates a private key using the previously stored parameters.</p>
     * @throws AlgorithmException if the key could not be generated.
     */
    public abstract PrivateKey getPrivateKey() throws AlgorithmException;

    /** 
     * <p>Generates a public key using the previously stored parameters.</p>
     * @throws AlgorithmException if the key could not be generated.
     */
    public abstract PublicKey getPublicKey() throws AlgorithmException;
    
    /**
     * <p>Wraps a public key and extracts its parameters.</p>
     * @param key The public key to wrap.
     * @throws AlgorithmException if the key could not be wrapped.
     */
    public abstract void wrapPublicKey(PublicKey key) throws AlgorithmException;
    
    /**
     * <p>Wraps a private key and extracts its parameters.</p>
     * @param key The private key to wrap.
     * @throws AlgorithmException if the key could not be wrapped.
     */
    public abstract void wrapPrivateKey(PrivateKey key) throws AlgorithmException;

}
