package test;

import junit.framework.TestCase;
import java.math.BigInteger;

/** Quick test to verify BigInteger's ability to verify hex digits
 * @version $Id: TestValidation.java,v 1.1 2007-07-10 09:12:42 nigelb Exp $
 */
public class TestValidation extends TestCase {
	// test hex strings
	private final static String hexDigits1 = "E399710FF5CB5278";
	private final static String hexDigits2 = "FFFFFFFFFFFFFFFF";
	private final static String hexDigits3 = "8000000000000000";
	private final static String hexDigits4 = "7FFFFFFFFFFFFFFF";
	private final static String hexDigits5 = "0000000000000000";
	
	private final static String badHexDigits1 = "FFFFFFFFFFFFFFFG";
	
	public void testValidation() {
		BigInteger hex1 = new BigInteger(hexDigits1, 16);
		BigInteger hex2 = new BigInteger(hexDigits2, 16);
		BigInteger hex3 = new BigInteger(hexDigits3, 16);
		BigInteger hex4 = new BigInteger(hexDigits4, 16);
		BigInteger hex5 = new BigInteger(hexDigits5, 16);
		
		System.out.println("Test 1 Bit Length: " + hex1.bitLength());
		System.out.println("Test 2 Bit Length: " + hex2.bitLength());
		System.out.println("Test 3 Bit Length: " + hex3.bitLength());
		System.out.println("Test 4 Bit Length: " + hex4.bitLength());
		System.out.println("Test 5 Bit Length: " + hex5.bitLength());
		
		try {
			BigInteger badHex1 = new BigInteger(badHexDigits1, 16);
			System.out.println("Should never get here: " + badHex1.bitLength());
			assertTrue(false);
		} catch(NumberFormatException e) {
			System.out.println("Test 6 Invalid Hex: " + badHexDigits1);
		}
	}
}
