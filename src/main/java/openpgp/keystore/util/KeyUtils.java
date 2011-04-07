package openpgp.keystore.util;

import java.math.BigInteger;
import java.io.ByteArrayOutputStream;
import core.algorithmhandlers.keymaterial.DSAAlgorithmParameters;
import core.algorithmhandlers.keymaterial.ElGamalAlgorithmParameters;
import core.algorithmhandlers.keymaterial.RSAAlgorithmParameters;
import core.algorithmhandlers.openpgp.util.PublicKeyAlgorithmSettings;
import core.algorithmhandlers.openpgp.packets.PacketHeader;
import core.algorithmhandlers.openpgp.packets.PublicKeyPacket;
import core.algorithmhandlers.openpgp.packets.SecretKeyPacket;
import core.algorithmhandlers.openpgp.packets.PublicSubkeyPacket;
import core.algorithmhandlers.openpgp.packets.SecretSubkeyPacket;
import core.exceptions.AlgorithmException;

/** Class containing utility methods for key handling
 * @version $Id: KeyUtils.java,v 1.2 2007-08-28 09:28:39 nigelb Exp $
 */
public class KeyUtils {
	
	/** Method to round the bit size onto a likely boundary */
	private static int getRoundedBitSize(int bitSize) {
		long div = Math.round((double)bitSize / 256);
		return (int)(div * 256);
	}
	
	/** Method to return the approximate, rounded-up size of the key, in bits
	 * @return An approximation of the key size - for example, although the 
	 * actual key in the key material might be 1022 bits or 1023 bits, the key
	 * size returned here would be 1024 bits.
	 */
	public static int getKeySize(PublicKeyPacket publicKey) {
		int keySize = 0;
		try {
			if (publicKey != null) {
				int algorithm = publicKey.getAlgorithm();
				if (PublicKeyAlgorithmSettings.isDSA(algorithm)) {
					DSAAlgorithmParameters params = 
							(DSAAlgorithmParameters)publicKey.getKeyData();
					keySize = getRoundedBitSize(params.getP().bitLength());
				} else if (PublicKeyAlgorithmSettings.isRSA(algorithm)) {
					RSAAlgorithmParameters params = 
							(RSAAlgorithmParameters)publicKey.getKeyData();
					keySize = getRoundedBitSize(params.getN().bitLength());
				} else if (PublicKeyAlgorithmSettings.isElGamal(algorithm)) {
					ElGamalAlgorithmParameters params = 
							(ElGamalAlgorithmParameters)publicKey.getKeyData();
					keySize = getRoundedBitSize(params.getP().bitLength());
				}
			}
		} catch (AlgorithmException e) {
			e.printStackTrace();
		}
		return keySize;
	}
	
	/** Method to convert a 64-bit word into a byte array 
	 * @param keyID The key identifier in long form
	 * @return A big-endian byte array representing the long
	 */
    public static byte[] toByteArray(long keyID) {
        byte[] result = new byte[8];
        result[7] = (byte)(keyID & 0xFFL);
        result[6] = (byte)((keyID >> 8) & 0xFFL);
        result[5] = (byte)((keyID >> 16) & 0xFFL);
        result[4] = (byte)((keyID >> 24) & 0xFFL);
        result[3] = (byte)((keyID >> 32) & 0xFFL);
        result[2] = (byte)((keyID >> 40) & 0xFFL);
        result[1] = (byte)((keyID >> 48) & 0xFFL);
        result[0] = (byte)((keyID >> 56) & 0xFFL);
        return result;
    }
    
    /** Method to convert a 32-bit word into a byte array 
	 * @param keyID The key identifier in long form
	 * @return A big-endian byte array representing the long
	 */
    public static byte[] toByteArray(int keyID) {
        byte[] result = new byte[4];
        result[3] = (byte)(keyID & 0xFF);
        result[2] = (byte)((keyID >> 8) & 0xFF);
        result[1] = (byte)((keyID >> 16) & 0xFF);
        result[0] = (byte)((keyID >> 24) & 0xFF);
        return result;
    }
    
    /** Method to test the validity of a key ID. The short key ID should be 4 
     * bytes, 8 hex digits, or the long key ID should be 8 bytes, 16 hex digits
     * @param keyID The key identifier, in hex, must be string length 8 or 16
     * @return Whether or not the value is a valid hexadecimal string
     */
    public static boolean isKeyIDValid(String keyID) {
        boolean isValid = false;
        if (keyID.length() == 8 || keyID.length() == 16) {
            try {
                new java.math.BigInteger(keyID, 16);
                isValid = true;
            } catch(NumberFormatException e) {}
        }
        return isValid;
    }
    
    /** Method to transform a hex string into a byte array
     * @param hexDigits The key identifier, in hex, should be length 8 or 16
     * @return an 8-byte big-endian number, representing the hex string, or a
     * byte array of all zero bytes if there was a problem
     */
    public static byte[] getKeyID(String hexDigits) {
    	byte[] result = new byte[8];
    	if (hexDigits.length() == 8 || hexDigits.length() == 16) {
            try {
            	byte[] ba = new BigInteger(hexDigits, 16).toByteArray();
            	int index = 0, len = ba.length;
            	if (ba.length > 8) {
            		for (int i = len - 8; i < len; ++i) {
            			result[index++] = ba[i];
            		}
            	} else if (ba.length < 8) {
            		for (int i = 8 - len; i < 8; ++i) {
            			result[i] = ba[index++];
            		}
            	} else {
            		result = ba;
            	}
            } catch(NumberFormatException e) {}
        }
    	return result;
    }
    
    /** Method to extract a public key packet from a secret key packet.
     * @param skp The secret key packet that also contains the public key
     * material
     * @return a corresponding public key packet, or null if it cannot be 
     * created
     */
    public static PublicKeyPacket getPublicKeyPacket(SecretKeyPacket skp) {
    	PublicKeyPacket pkp = null;
    	try {
    		// Firstly, construct the packet body
        	ByteArrayOutputStream out = new ByteArrayOutputStream();
        	// write the version
        	out.write(0x04);
        	// write created date
            out.write((int)((skp.getCreateDate() >> 24) & 0xFF));
            out.write((int)((skp.getCreateDate() >> 16) & 0xFF));
            out.write((int)((skp.getCreateDate() >> 8) & 0xFF));
            out.write((int)((skp.getCreateDate() >> 0) & 0xFF));
            // write the algorithm
            out.write(skp.getAlgorithm() & 0xFF);
            // write the public key components
        	out.write(skp.getKeyData().encodePublicKeyComponents());
        	
        	byte[] packetBody = out.toByteArray();
        	out.close();
        	
        	// construct the packet
        	PublicKeyPacket p = new PublicKeyPacket();
        	p.setPacketHeader(new PacketHeader(6, false, packetBody.length));
        	p.buildPacket(packetBody);
        	
        	// if all goes well, the completed packet can be returned
        	pkp = p;
    	} catch(Exception e) {
    		e.printStackTrace();
    	}
    	return pkp;
    }
    
    /** Method to extract a public subkey packet from a secret subkey packet.
     * @param ssp The secret subkey packet that also contains the public subkey
     * material
     * @return a corresponding public subkey packet, or null if it cannot be 
     * created
     */
    public static PublicSubkeyPacket getPublicSubkeyPacket(SecretSubkeyPacket ssp) {
    	PublicSubkeyPacket psp = null;
    	try {
    		// Firstly, construct the packet body
        	ByteArrayOutputStream out = new ByteArrayOutputStream();
        	// write the version
        	out.write(0x04);
        	// write created date
            out.write((int)((ssp.getCreateDate() >> 24) & 0xFF));
            out.write((int)((ssp.getCreateDate() >> 16) & 0xFF));
            out.write((int)((ssp.getCreateDate() >> 8) & 0xFF));
            out.write((int)((ssp.getCreateDate() >> 0) & 0xFF));
            // write the algorithm
            out.write(ssp.getAlgorithm() & 0xFF);
            // write the public key components
        	out.write(ssp.getKeyData().encodePublicKeyComponents());
        	
        	byte[] packetBody = out.toByteArray();
        	out.close();
        	
        	// construct the packet
        	PublicSubkeyPacket p = new PublicSubkeyPacket();
        	p.setPacketHeader(new PacketHeader(14, false, packetBody.length));
        	p.buildPacket(packetBody);
        	
        	// if all goes well, the completed packet can be returned
        	psp = p;
    	} catch(Exception e) {
    		e.printStackTrace();
    	}
    	return psp;
    }
    
}