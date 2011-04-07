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

package core.email.encoders;
import java.io.*;

/**
 * <p>A class that contains utility methods for encoding and decoding binary data to and from
 * Quoted printable MIME encoding. </p>
 * <p>Quoted printable text is pretty much 7bit ascii, but has a line length limit of 76 chars. Long lines are truncated with a soft
 * line break "=" and special characters are =xx escaped.</p>
 */
public class QuotedPrintable {

    /** The maximum line length */
    private static final int MAX_LINE_LENGTH = 70;
    
    /** 
     * <p>Takes an array of byte and returns the 7bit mime encoding of it.</p>
     * <p>Since the byte array should already be text, this primarily involves wrapping long lines with
     * soft line breaks ("=").</p>
     */
    public static byte[] encode(byte data[]) throws IOException {
        throw new IOException("Method not implemented");
    }
    
    /** 
     * <p>Removes soft line breaks in the data and converts "=" escaped characters back to normal. </p>
     * <p>Returns the raw 7bit ascii version of the text.</p>
     */
    public static byte[] decode(byte data[]) throws IOException {
        BufferedReader in = new BufferedReader(new InputStreamReader(new ByteArrayInputStream(data)));
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        while (in.ready()) {
            String s = in.readLine();

            if (s.endsWith("=")) {
                // handle soft line break
                s = s.substring(0,s.length()-1);
                out.write(decodeEscaping(s));
            } else {
                out.write(decodeEscaping(s));
                out.write("\r\n".getBytes());
            }
        }

        return out.toByteArray();
    }
    
    /** Decode the =XX escaping contained inside a document. */
    private static byte [] decodeEscaping(String line) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        
        int n = 0;
        while (n<line.length()) {
            if (line.charAt(n)=='=') {
                try {
                    out.write(Integer.parseInt(line.substring(n+1,n+3), 16));
                } catch (NumberFormatException nfe) {
                    throw new IOException("Invalid quoted-printable encoded data");
                }
                
                n+=3;
            } else {
                out.write(line.charAt(n));
                n++;
            }
        }
        
        return out.toByteArray();
    }
}
