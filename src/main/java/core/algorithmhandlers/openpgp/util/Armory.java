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

package core.algorithmhandlers.openpgp.util;
import core.exceptions.AlgorithmException;
import core.exceptions.ChecksumFailureException;
import core.email.encoders.Base64;
import java.io.*;
import java.lang.StringBuffer;
import java.lang.String;

/**
 * <p>This class creates and converts ascii armor messages.</p>
 * <p>The class will convert to and from base64 encoding, and verify checksums. 
 * you must however construct the header information yourself.</p>
 */
public class Armory {
    
    /**
     * Produces the armored version of a given array of bytes. You still have to add the header and footer tags yourself. 
     */
    public static String armor(byte message[]) {
        
        // calculate CRC
        int crcInt = (int)CRC24.crcOctets(message);
        byte crcBytes[] = new byte[3];
        crcBytes[0] = (byte)(crcInt >> 16);
        crcBytes[1] = (byte)(crcInt >> 8);
        crcBytes[2] = (byte)(crcInt);
        
        return new String(Base64.encode(message)) + "=" + new String(Base64.encode(crcBytes));
    }
    
    /** 
     * This method verifies the crc and returns a raw byte encoded string containing the PGP packet(s).
     * @param message The ascii armored message (without the header and footer).
     * @throws AlgorithmException if the message could not be coded.
     * @throws ChecksumFailureException If the checksum does not match.
     */
    public static byte[] disarm(String message) throws AlgorithmException, ChecksumFailureException {

        try {
            int crcPos = message.indexOf("\r\n=");

            String armoredEncodedMessage = message.substring(0, crcPos);
            byte[] mainMessage = Base64.decode(armoredEncodedMessage.getBytes());

            String crcEncodedString = message.substring( crcPos + 3, crcPos + 7 );
            byte[] crcBytes = Base64.decode(crcEncodedString.getBytes());

            int crcInt = ((crcBytes[0] & 0xFF) << 16) | ((crcBytes[1] & 0xFF) <<  8) | ((crcBytes[2] & 0xFF));
            int calculatedCRC = (int)CRC24.crcOctets(mainMessage);

            if (crcInt != calculatedCRC)
                throw new ChecksumFailureException("CRC failed while decoding ascii armored message.");

            return mainMessage;

        } catch (StringIndexOutOfBoundsException e) {
            throw new AlgorithmException("Armored data is incomplete.");
        }    
    }
    
    /**
     * This method will dash-escape the clear text passed to it. Use this for constructing clear text armor 
     * around a message.
     * @throws AlgorithmException if there was a problem.
     */
    public static String dashEscapeText(String message) throws AlgorithmException {
        try {
            StringBuffer out = new StringBuffer();
            BufferedReader in = new BufferedReader(new StringReader(message));

            String s;

            while ((s=in.readLine()) != null) {
                if (s.startsWith("-")) 
                    out.append("- " + s + "\r\n");
                else 
                    out.append(s + "\r\n");
            }

            return out.toString();
        } catch (IOException e) {
            throw new AlgorithmException(e.getMessage());
        }
    }
    
    /** 
     * This method will remove dash escaping.
     * @throws AlgorithmException if there was a problem.
     */
    public static String removeDashEscaping(String message) throws AlgorithmException {
        try {
            StringBuffer out = new StringBuffer();
            BufferedReader in = new BufferedReader(new StringReader(message));

            String s;

            while ((s=in.readLine()) != null) {
                if (s.startsWith("- ")) 
                    out.append(s.substring(2) + "\r\n");
                else 
                    out.append(s + "\r\n");
            }

            return out.toString();
        } catch (IOException e) {
            throw new AlgorithmException(e.getMessage());
        }
    }
    
    /** 
     * <p>Format a message to produce a value suitable for clear text signing.</p>
     * <p>This clears the last cr/lf pair and removes trailing whitespace, making it suitable for signing.</p>
     */
    public static byte[] formatForCTSigning(byte [] message) throws AlgorithmException {
        try {
            BufferedReader in = new BufferedReader(new InputStreamReader(new ByteArrayInputStream(message)));
            ByteArrayOutputStream out = new ByteArrayOutputStream();

            String s = new String();
            while (in.ready()) {
                s = in.readLine();
                
                if ((s!=null) && (s.length()>0)) {
                    // strip end whitespace
                    int index = s.length()-1;
                    while ( (s.charAt(index)=='\t') || (s.charAt(index)==' ') || (s.charAt(index)==0x09) ) {
                        index--;
                    }
              
                    out.write(s.substring(0, index+1).getBytes());
                }
                
                out.write("\r\n".getBytes());
            }
            
            return out.toString().substring(0,out.toString().lastIndexOf("\r")).getBytes();
        } catch (IOException e) {
            throw new AlgorithmException(e.getMessage());
        }
    }
}
