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
 * <p>Test the creation of a CompressedDataPacket class.</p>
 */
public class TestCompressedDataPacket extends TestCase 
{
	/** Output filename. */
	public final String outputfile = "TestCompressedDataPacket.packet";
	
	/* Literal packet data 1 */
	public final byte format_1 = 't';
	public final String rawdata_1 = "This is some literal data";
	public final String filename_1 = "AFilename.dat";
	
	/* Literal packet data 2 */
	public final byte format_2 = 't';
	public final String rawdata_2 = "This is some more literal data";
	public final String filename_2 = "AnotherFilename.dat";
    
	/** <p>Execute the test.</p>
	 * <p>You should implement this method with your test. Return true if the test
	 * was successful, otherwise return false.</p>
	 */
	public void testCompressedDataPacket()
	{
        boolean allOK = true;

        try
        {
			// create literal data packet
			System.out.println("Creating new CompressedDataPacket with ZIP compression...");
			CompressedDataPacket cp_uncompressed = new CompressedDataPacket((byte)1);
			
			System.out.println("Creating and adding first literal packet...");
			LiteralDataPacket p1 = new LiteralDataPacket(format_1, filename_1,  rawdata_1.getBytes());
			
			System.out.println("Creating and adding second literal packet...");
			LiteralDataPacket p2 = new LiteralDataPacket(format_2, filename_2,  rawdata_2.getBytes());
			
			System.out.println("Adding packets...");
			cp_uncompressed.add(p1);
			cp_uncompressed.add(p2);
			
			// write it out
			System.out.println("Writing packets to file...");
			System.out.println("  Opening packet stream to "+outputfile+"...");
			OpenPGPPacketOutputStream stream = new OpenPGPPacketOutputStream(new FileOutputStream(outputfile));
			
			System.out.println("  Writing compressed packet...");
			stream.writePacket(cp_uncompressed);
			
			System.out.println("  Closing stream...");
			stream.close();
			
			// read it in
			System.out.println("Reading packets from file...");
			System.out.println("  Opening packet stream to "+outputfile+"...");
			OpenPGPPacketInputStream instream = new OpenPGPPacketInputStream(new FileInputStream(outputfile));
			
			System.out.println("  Reading compressed packet ...");
			CompressedDataPacket r_p = (CompressedDataPacket)instream.readPacket();
			
			System.out.println("  Closing stream...");
			instream.close();
			
			// compare packet 1
			System.out.println("Comparing packet 1...");
			
			LiteralDataPacket lp1 = (LiteralDataPacket)r_p.unpack(0);
	
			// format
			System.out.print( "  Format... " );
			if( lp1.getFormat() == format_1 )
			{
				// ok
				System.out.println( "Ok" );
			}
			else
			{
				// error
				System.out.print( lp1.getFormat() );
				System.out.println( "...Error!" );
				allOK = false;
			}
	
			// Filename
			System.out.print( "  Filename... " );
			if( lp1.getFilename().compareTo( filename_1 ) == 0 )
			{
				// ok
				System.out.println( "Ok" );
			}
			else
			{
				// error
				System.out.print( lp1.getFilename() );
				System.out.println( "Error!" );
				allOK = false;
			}
	
			// data only
			System.out.print( "  Data... " );
			if( new String( lp1.getData() ).compareTo( rawdata_1 ) == 0 )
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
			System.out.println(new Date(lp1.getModDate()*1000).toString());
			
			// compare packet 2
			System.out.println("Comparing packet 2...");
			
			LiteralDataPacket lp2 = (LiteralDataPacket)r_p.unpack(1);
	
			// format
			System.out.print( "  Format... " );
			if( lp2.getFormat() == format_2 )
			{
				// ok
				System.out.println( "Ok" );
			}
			else
			{
				// error
				System.out.print( lp2.getFormat() );
				System.out.println( "...Error!" );
				allOK = false;
			}
	
			// Filename
			System.out.print( "  Filename... " );
			if( lp2.getFilename().compareTo( filename_2 ) == 0 )
			{
				// ok
				System.out.println( "Ok" );
			}
			else
			{
				// error
				System.out.print( lp2.getFilename() );
				System.out.println( "Error!" );
				allOK = false;
			}
	
			// data only
			System.out.print( "  Data... " );
			if( new String( lp2.getData() ).compareTo( rawdata_2 ) == 0 )
			{
				// ok
				System.out.println( "Ok" );
			}
			else
			{
				// error
				System.out.println( new String( lp2.getData() ) );
				System.out.println( "Error!" );
				allOK = false;
			}
			
			// Date
			System.out.print("  Date is... ");
			System.out.println(new Date(lp2.getModDate()*1000).toString());
        }
        catch( Exception e )
        {
        	e.printStackTrace();
        	allOK = false;
        }
        
        assertTrue( allOK );
    }
    
}
