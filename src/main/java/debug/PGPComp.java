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
 * <p>PGP File compiler.</p>
 * <p>This program takes a list of packet files and combines them into a given file.</p>
 */
public class PGPComp {
    
    /** Version number */
    private static String version = "v1.0";
    
    
    /** Creates a new instance of PGPComp */
    public PGPComp() {
    }
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        if (args.length <= 1) {
            System.out.println("PGPComp - PGP File compiler " + version + " : By Marcus Povey");
            System.out.println();
            System.out.println("Usage: java test.PGPComp <target> <pgppackets...>");
        } else {
            try {
                System.out.println("Opening packet stream to "+args[0]+"...");
                OpenPGPPacketOutputStream out = new OpenPGPPacketOutputStream(new FileOutputStream(args[0]));
                
                for (int n=1; n<args.length; n++) {
                    System.out.println("Reading "+args[n]+"...");
                    OpenPGPPacketInputStream in = new OpenPGPPacketInputStream(new FileInputStream(args[n]));
                    
                    out.writePacket(in.readPacket());

                    in.close();
                }
                
                System.out.println("Closing stream...");
                out.close();

            } catch (Exception e) {
                System.err.println(e.getMessage());
            }
        }
    }
    
}
