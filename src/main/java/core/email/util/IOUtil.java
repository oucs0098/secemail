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

package core.email.util;
import java.io.*;

/**
 * A utility class containing various useful IO routiens for simplifying some aspects of data parsing.</p>
 */
public class IOUtil {
    
    /** Creates a new instance of Util */
    public IOUtil() {
    }
    
    /** 
     * <p>Read a full line from an input stream, returning it in a string. </p>
     * <p>Written because there are issues attached to using buffered readers in this context. </p>
     * @param in The stream to read from.
     * @return the line, or a zero length string if like was empty (other than end of line chars).
     */
    public static String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        
        int b = in.read();
        while ( (b != '\r') && (b != '\n') && (b != -1)) {
            out.write(b);
            b = in.read();
        }

        if (b == '\r') in.read(); // if there is a \r then next line will be a \n.. so skip it

        return out.toString();
    }
}
