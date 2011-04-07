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
import java.util.*;

/**
 * <p>Test the creation of a LiteralDataPacket class.</p>
 */
public class TestLiteralDataPacket extends TestCase
{
	/** Output filename. */
	public final String outputfile = "TestLiteralDataPacket.packet";
	public final byte format = 't';
	public final String rawdata = "This is some literal data";
	public final String filename = "AFilename.dat";
    
	/** <p>Execute the test.</p>
	 * <p>You should implement this method with your test. Return true if the test
	 * was successful, otherwise return false.</p>
	 */
	public void testLiteralDataPacket()
	{
		boolean allOK = true;
		
		try
		{
			// create literal data packet
			System.out.println("Creating new LiteralDataPacket...");
			
			// todo create packet
			LiteralDataPacket p = new LiteralDataPacket(format, filename, rawdata.getBytes());
			
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
			System.out.println("Comparing...");
			
			LiteralDataPacket lp = (LiteralDataPacket)p2;
	
			// format
			System.out.print( "  Format... " );
			if( lp.getFormat() == format )
			{
				// ok
				System.out.println( "Ok" );
			}
			else
			{
				// error
				System.out.print( lp.getFormat() );
				System.out.println( "...Error!" );
				allOK = false;
			}
	
			// Filename
			System.out.print( "  Filename... " );
			if( lp.getFilename().compareTo( filename ) == 0 )
			{
				// ok
				System.out.println( "Ok" );
			}
			else
			{
				// error
				System.out.print( lp.getFilename() );
				System.out.println( "Error!" );
				allOK = false;
			}
	
			// data only
			System.out.print( "  Data... " );
			if( new String( lp.getData() ).compareTo( rawdata ) == 0 )
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
			
			// Date
			System.out.print("  Date is... ");
			System.out.println(new Date(lp.getModDate()*1000).toString());
		}
		catch( Exception e )
		{
			e.printStackTrace();
			allOK = false;
		}
		
        // tell JUnit how the test went ...
        assertTrue( allOK );
    }
    
}
