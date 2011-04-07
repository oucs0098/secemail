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

package debug;
import core.algorithmhandlers.openpgp.*;
import core.algorithmhandlers.openpgp.packets.*;
import core.algorithmhandlers.keymaterial.*;
import core.algorithmhandlers.openpgp.util.*;
import core.email.encoders.*;
import java.io.*;

/**
 * A quick program to encode a given file to base 64 mime encoding.
 */
public class Base64Encode {
    
    /** Version number */
    private static String version = "v1.0";
    
    
    
    /** Creates a new instance of Base64Encode */
    public Base64Encode() {
    }
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        if (args.length <= 1) {
            System.out.println("Base64Encode - Base64 file encoder " + version + " : By Marcus Povey");
            System.out.println();
            System.out.println("Usage: java test.Base64Encode <file> <encodedfile>");
        } else {
            try {
                
                FileInputStream r = new FileInputStream(args[0]);
           
                System.out.println("Reading...");
                byte [] decoded = new byte[r.available()];
                r.read(decoded);
                r.close();

                System.out.println("Decoding...");
                byte [] raw = Base64.encode(decoded);

                System.out.println("Writing...");
                FileOutputStream fo = new FileOutputStream(args[1]);
                fo.write(raw);
                fo.close();

            } catch (Exception e) {
                System.err.println(e.getMessage());
            }
        }
    }
    
}
