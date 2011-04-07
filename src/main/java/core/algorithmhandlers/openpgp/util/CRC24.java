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

/**
 * A utility class for creating a CRC-24 checksum. Based on the C implementation given in RFC2440.
 */
public class CRC24 {
       
    /** A method to produce the CRC 24 checksum of a given array of bytes. */
    public static long crcOctets(byte octets[]) {
        long crc = 0xb704ceL;
        
        int len = octets.length;
        int pos = 0;
        
        while (len-- > 0 ) {
            crc ^= (octets[pos++]) << 16;
            for (int i = 0; i < 8; i++) {
                crc <<= 1;
                
                if ((crc & 0x1000000)>0)
                    crc ^= 0x1864cfbL;
            }
        }
        
        return crc & 0xffffffL;
    }
}
