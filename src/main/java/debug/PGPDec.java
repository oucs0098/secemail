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
import java.util.*;
import java.io.*;

/**
 * <p>PGP File decompiler.</p>
 * <p>This program takes a given packet file and breaks it up into individual packet files. These can be recombined using PGPComp.</p>
 * <p>Note: This is NOT recursive, so packets which contain other packets (for example a Compressed Data Packet) will NOT be decompiled.</p>
 */
public class PGPDec {
    /** Version number */
    private static String version = "v1.0";
    
    /** Creates a new instance of PGPDec */
    public PGPDec() {
    }
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("PGPDec - PGP File Decompiler " + version + " : By Marcus Povey");
            System.out.println();
            System.out.println("Usage: java test.PGPDec <filename>");
        } else {
            try {
                System.out.println("Opening packet stream to "+args[0]+"...");
                OpenPGPPacketInputStream in = new OpenPGPPacketInputStream(new FileInputStream(args[0]));

                System.out.println("Reading packet stream...");
                int n = 1;
                
                Packet p = null;
                do {

                    p = in.readPacket();

                    if (p!=null) {
                        OpenPGPPacketOutputStream out = new OpenPGPPacketOutputStream(new FileOutputStream(String.valueOf(n) + ".packet"));
                        System.out.println("Writing " + String.valueOf(n) + ".packet");
                        
                        out.writePacket(p);
                        
                        out.close();
                    }
                    
                    n++;
                } while (p!=null);
                
                System.out.println("Closing stream...");
                in.close();
            
            } catch (Exception e) {
                System.err.println(e.getMessage());
                e.printStackTrace();
            }
        }
    }
    
}
