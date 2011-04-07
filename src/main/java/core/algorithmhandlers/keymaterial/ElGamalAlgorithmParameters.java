package core.algorithmhandlers.keymaterial;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import core.algorithmhandlers.openpgp.util.MPI;
import core.exceptions.AlgorithmException;

import org.bouncycastle.jce.spec.ElGamalPublicKeySpec;
import org.bouncycastle.jce.spec.ElGamalPrivateKeySpec;
import org.bouncycastle.jce.spec.ElGamalParameterSpec;
import org.bouncycastle.jce.interfaces.ElGamalKey;
import org.bouncycastle.jce.interfaces.ElGamalPublicKey;
import org.bouncycastle.jce.interfaces.ElGamalPrivateKey;

/**
 * <p>This class acts as a wrapper for the ElGamal algorithm parameters.</p>
 * <p>This class also provides a convenient way to load and save the parameters 
 * in keyring format.</p>
 */
public class ElGamalAlgorithmParameters extends AsymmetricAlgorithmParameters {

	/** Public key components */
    MPI p,		// large prime number
        g,		// some number that is relatively prime to p (and is smaller than p)
        y;		// public exponent
    
    /** Private key components */
    MPI x;		// private exponent
    
    /** Creates a new instance of DSAAlgorithmParameters */
    public ElGamalAlgorithmParameters() {
		p = null;
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
        
    /** <p>Create an algorithm parameter out of encoded secret key component 
     * data.</p>
     * @param stream A byte array containing the encoded data for this algorithm 
     * according to the OpenPGP spec.
     * @throws AlgorithmException if something went wrong.
     *
     */
    public void decodePrivateKeyComponents(InputStream stream)
			throws AlgorithmException {
		x = new MPI(stream);
	}
    
    /** <p>Create an algorithm parameter out of encoded public key component 
     * data.</p>
     * @param stream A byte stream containing the encoded data for this algorithm 
     * according to the OpenPGP spec.
     * @throws AlgorithmException if something went wrong.
     *
     */
    public void decodePublicKeyComponents(InputStream stream)
			throws AlgorithmException {
		p = new MPI(stream);
		g = new MPI(stream);
		y = new MPI(stream);
	}
    
    /**
     * <p>Produce a encoded version of the algorithms private key components 
     * according to the
     * OpenPGP Secret Key Packet format.</p>
     * <p>Encodes the algorithm specific public key MPIs according in the order 
     * described in the OpenPGP spec
     * for the specific algorithm.</p>
     * @throws AlgorithmException if something went wrong.
     *
     */
    public byte[] encodePrivateKeyComponents() throws AlgorithmException {
		return x.toByteArray();
	}
    
    /**
     * <p>Produce a encoded version of the algorithms public key components 
     * according to the
     * OpenPGP Public Key Packet format.</p>
     * <p>Encodes the algorithm specific public key MPIs according in the order 
     * described in the OpenPGP spec
     * for the specific algorithm.</p>
     * @throws AlgorithmException if something went wrong.
     *
     */
    public byte[] encodePublicKeyComponents() throws AlgorithmException {
		try {
			ByteArrayOutputStream out = new ByteArrayOutputStream();

			out.write(p.toByteArray());
			out.write(g.toByteArray());
			out.write(y.toByteArray());

			return out.toByteArray();

		} catch (IOException e) {
			throw new AlgorithmException(e.getMessage());
		}
	}
    
    /**<p>Generate a new key pair and save its parameters.</p>
	 * @param keysize The key size to generate.
	 * @param random A random number generator to use to generate the key.
	 * @throws AlgorithmException if something went wrong.
	 */
    public void generateKeyPair(int keysize, SecureRandom random)
			throws AlgorithmException {
		try {
			KeyPairGenerator k = KeyPairGenerator.getInstance("ElGamal", "BC");
			k.initialize(keysize, random);

			KeyPair kp = k.generateKeyPair();

			wrapPublicKey(kp.getPublic());
			wrapPrivateKey(kp.getPrivate());
		} catch (Exception e) {
			throw new AlgorithmException(e.getMessage());
		}
	}
    
    /** <p>Generates a private key using the previously stored parameters.</p>
	 * @throws AlgorithmException if the key could not be generated.
	 */
    public PrivateKey getPrivateKey() throws AlgorithmException {
		if (x == null)
			throw new AlgorithmException(
					"Not enough key material to construct Private key");

		try {
			KeyFactory keyFactory = KeyFactory.getInstance("ElGamal", "BC");
			System.out.println("xxx Got ElGamal key factory...");

			ElGamalPrivateKeySpec privateKeySpec = new ElGamalPrivateKeySpec(
					getX(), new ElGamalParameterSpec(getP(), getG()));

			return keyFactory.generatePrivate(privateKeySpec);

		} catch (Exception e) {
			throw new AlgorithmException(e.getMessage());
		}
	}
    
    /** <p>Generates a public key using the previously stored parameters.</p>
	 * @throws AlgorithmException if the key could not be generated.
	 */
    public PublicKey getPublicKey() throws AlgorithmException {
		if ((p == null) || (g == null) || (y == null))
			throw new AlgorithmException(
					"Not enough key material to construct Public key");

		try {
			KeyFactory keyFactory = KeyFactory.getInstance("ElGamal", "BC");

			ElGamalPublicKeySpec publicKeySpec = new ElGamalPublicKeySpec(
					getY(), new ElGamalParameterSpec(getP(), getG()));

			return keyFactory.generatePublic(publicKeySpec);
		} catch (Exception e) {
			throw new AlgorithmException(e.getMessage());
		}
	}
    
    /** <p>Wraps a private key and extracts its parameters.</p>
	 * @param key The private key to wrap.
	 * @throws AlgorithmException if the key could not be wrapped.
	 */
    public void wrapPrivateKey(PrivateKey key) throws AlgorithmException {
		if (!(key instanceof ElGamalKey))
			throw new AlgorithmException(
					"ElGamalAlgorithmParameters class can not wrap a non-" +
					"ElGamal key!");

		ElGamalPrivateKey eg = (ElGamalPrivateKey) key;

		setX(eg.getX());
	}
    
    /** <p>Wraps a public key and extracts its parameters.</p>
	 * @param key The public key to wrap.
	 * @throws AlgorithmException if the key could not be wrapped.
	 */
    public void wrapPublicKey(PublicKey key) throws AlgorithmException {
		if (!(key instanceof ElGamalKey))
			throw new AlgorithmException(
					"ElGamalAlgorithmParameters class can not wrap a non-" +
					"ElGamal key!");

		ElGamalPublicKey eg = (ElGamalPublicKey) key;

		setP(eg.getParameters().getP());
		setG(eg.getParameters().getG());
		setY(eg.getY());
	}

}
