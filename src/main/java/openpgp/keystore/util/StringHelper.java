package openpgp.keystore.util;

/** String utility class */
public class StringHelper {
	
	/** Conversion method to convert bytes to hex strings. This method includes
	 * leading zeroes (e.g. if a byte is 0 the hex representation will be '00').
	 * @param b an array of bytes to be converted
	 * @return The hex representation of the bytes, as a String 
	 */
	public static String toHexString(byte[] b) {
		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < b.length; ++i) {
			String h = Integer.toHexString(b[i] & 0xFF).toUpperCase();
			if (h.length() == 1) sb.append("0");
			sb.append(h);
		}
		return sb.toString();
	}
	
	/** Method to preserve backslashes in Windows file path strings */
    public static String escapeWinPath(String path) {
    	String retval = path.replaceAll(":\\\\\\b", ":\\\\\\\\");
    	return retval.replaceAll("\\b\\\\\\b", "\\\\\\\\");
    }
    
    /** Method to change double-backslashes to single backslashes for display */
    public static String reduceWinPath(String path) {
    	return path.replaceAll("\\\\\\\\", "\\\\");
    }
	
}
