package openpgp.keystore.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

/** Stream utility class */
public class StreamHelper {
	
	/** <p>Read a full line from an input stream, returning it in a string.</p>
     * <p>Written because there are issues attached to using buffered readers
     * in this context.</p>
     * @param in The stream to read from.
     * @return the line, or a zero length string if like was empty (other than
     * end of line chars).
     */
    public static String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int b = in.read();
        while ( (b != '\r') && (b != '\n') && (b != -1)) {
            out.write(b);
            b = in.read();
        }
        //if there is a \r then next line will be a \n.. so skip it
        if (b == '\r') in.read();
        if ((b==-1) && (out.size()==0)) return null;
        
        return out.toString();
    }
    
}
