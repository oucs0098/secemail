package openpgp.keystore.util;

import java.math.BigInteger;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAParams;
import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;
import core.exceptions.AlgorithmException;

/** Because I'm not sure whether the SUN provider and the BC provider are 
 * generating DSA signatures that are recognised as good signatures by PGP
 * and GnuPG, here's an alternative implementation, based on the Schneier 
 * description of DSA. This is here to try to narrow down the 'DSA not 
 * working' problem (see Brookes Secure Email Proxy last release notes).
 * @version $Id: DSASignatureGenerator.java,v 1.1 2007-08-07 13:15:57 nigelb Exp $
 */
public class DSASignatureGenerator {
	
	/** pseudo-random number generator */
	SecureRandom random;
	
	/** Constructor, sets up the PRNG */
	public DSASignatureGenerator() throws NoSuchAlgorithmException {
		random = SecureRandom.getInstance("SHA1PRNG");
	}
	
	/** Method to generate a DSA signature from a private key and a hash.
	 * @param privateKey The DSA private key object
	 * @param messageHash The hash of the message, can be any 160-bit digest 
	 * @return An object containing the DSA signature elements R and S
	 * @throws AlgorithmException if the message digest is not of the correct
	 * size
	 */
	public DSASignature generateDSASignature(DSAPrivateKey privateKey,
			byte[] messageHash) throws AlgorithmException {
		
		if (messageHash.length != 20) {
			throw new AlgorithmException(
					"DSA cannot deal with digests other than 160 bits long");
		}
		
		DSAParams dsaParams = privateKey.getParams();
		BigInteger p = new BigInteger(1, dsaParams.getP().toByteArray());
		BigInteger q = new BigInteger(1, dsaParams.getQ().toByteArray());
		BigInteger g = new BigInteger(1, dsaParams.getG().toByteArray());
		BigInteger x = new BigInteger(1, privateKey.getX().toByteArray());
		BigInteger k = generateK(q);
		BigInteger r, s;
		
		r = g.modPow(k, p);
		r = r.mod(q);
		
		BigInteger kInv = k.modInverse(q);
		BigInteger mHash = new BigInteger(1, messageHash);
		BigInteger tmp;
		
		tmp = x.multiply(r);
		tmp = tmp.add(mHash);
		tmp = tmp.multiply(kInv);
		s = tmp.mod(q);
		
		debug.Debug.println(1, "          R: " + 
				StringHelper.toHexString(r.toByteArray()));
		debug.Debug.println(1, "          S: " + 
				StringHelper.toHexString(s.toByteArray()));
		
		return new DSASignature(r, s);
	}
	
	/** Method to generate a random number k, where 0 < k < q
	 * @param q The 'Q' parameter from the DSA public/private key - the 
	 * generated number k must be less than Q (and greater than 0).
	 */
	private BigInteger generateK(BigInteger q) {
		byte[] qBytes = q.toByteArray();
		byte[] rand = new byte[qBytes.length];
		random.nextBytes(rand);
		int n = 0;
		n += ((qBytes[0] & 0xFF) << 24);
		n += ((qBytes[1] & 0xFF) << 16);
		n += ((qBytes[2] & 0xFF) << 8);
		n += (qBytes[3] & 0xFF);
		n = random.nextInt(n);
		rand[0] = (byte)((n >> 24) & 0xFF);
		rand[1] = (byte)((n >> 16) & 0xFF);
		rand[2] = (byte)((n >> 8) & 0xFF);
		rand[3] = (byte)(n & 0xFF);
		return new BigInteger(1, rand);
	}
}
