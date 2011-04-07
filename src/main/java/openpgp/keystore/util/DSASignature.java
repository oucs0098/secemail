package openpgp.keystore.util;

import java.math.BigInteger;

/** Simple bean-type class to wrap a pair of large integer values, which 
 * together make up a DSA signature.
 */
public class DSASignature {
	
	/** The signature values */
	private BigInteger r, s;
	
	/** The sole constructor
	 * @param r Part of the DSA signature
	 * @param s Part of the DSA signature
	 */
	public DSASignature(BigInteger r, BigInteger s) {
		this.r = r;
		this.s = s;
	}
	
	/** Accessor method */
	public BigInteger getR() {
		return r;
	}
	
	/** Accessor method */
	public BigInteger getS() {
		return s;
	}
}
