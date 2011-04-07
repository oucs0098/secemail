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

package test;

import core.algorithmhandlers.openpgp.*;
import core.algorithmhandlers.openpgp.packets.*;
import junit.framework.TestCase;
import java.io.*;


/**
 * <p>Tests the user id packet.</p>
 * <p>The test creates a new User ID packet, writes it to a file and then attempts to read it back in.</p>
 * <p>If TestOpenPGPPacketInputStream has successfully been tested then a successful completion of this test
 * will mean that the user id packet is working correctly and can be successfully encoded.</p>
 */
public class TestUserIDPacket extends TestCase {
    
    /** Output filename. */
    public final String outputfile = "TestUserIDPacket.packet";
    
    /** ID info to write */
    public final String id = "Marcus Povey <icewing@dushka.co.uk>";
    
    /** <p>Execute the test.</p>
     * <p>You should implement this method with your test. Return true if the test
     * was successful, otherwise return false.</p>
     */
    public boolean doTest()
    {
    	boolean allOK = true;
    	
    	try
    	{
			// create id packet
			System.out.println("Creating new UserIDPacket...");
			UserIDPacket p = new UserIDPacket(id.getBytes());
			
			// write it out
			System.out.println("Writing packet to file...");
			System.out.println("  Opening packet stream to "+outputfile+"...");
			OpenPGPPacketOutputStream stream = new OpenPGPPacketOutputStream(new FileOutputStream(outputfile));
			
			System.out.println("  Writing packet...");
			stream.writePacket(p);
			
			System.out.println("  Closing stream...");
			stream.close();
			
			// read it in
			System.out.println("Reading packet from file...");
			System.out.println("  Opening packet stream to "+outputfile+"...");
			OpenPGPPacketInputStream instream = new OpenPGPPacketInputStream(new FileInputStream(outputfile));
			
			System.out.println("  Reading packet...");
			Packet p2 = instream.readPacket();
			
			System.out.println("  Closing stream...");
			instream.close();
			
			// compare id with saved id.
			System.out.print("Comparing...");
			UserIDPacket uidp = (UserIDPacket)p2;
			if( id.compareTo( new String( uidp.getID() ) ) == 0 )
			{
				// ok
				System.out.println( "Ok" );
			}
			else
			{
				// error
				System.out.println( "Error!" );
				allOK = false;
			}
		}
		catch( Exception e )
		{
			e.printStackTrace();
			allOK = false;
		}
    	
        // if we got this far then the test should have gone ok
        return allOK;
    }
    
    public void testUserIDPacket()
    {
    	assertTrue( doTest() );
    }
    
}
