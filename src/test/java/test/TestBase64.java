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

import core.email.encoders.*;
import core.algorithmhandlers.openpgp.*;
import core.algorithmhandlers.openpgp.packets.*;
import junit.framework.TestCase;
import java.io.*;
import java.util.*;

/**
 * <p>A simple base 64 encoding test.</p> 
 * <p>Will create a literal data packet, encoded to radix encoding, write it out and then read it back in comparing the result.</p>
 */
public class TestBase64 extends TestCase {
    
	/** Output filename. */
	public final String outputfile = "TestBase64.packet";
	public final byte format = 't';
	public final String rawdata = "This is some literal data. Actually... this is a lot of literal data used to make sure that the thingy does the wrap around thing and that I can still read it. cool eh? :D anyway... i had better stop typing and see if it works now. ";
	public final String filename = "AFilename.dat";
    
	/** <p>Execute the test.</p>
	 * <p>You should implement this method with your test. Return true if the test
	 * was successful, otherwise return false.</p>
	 */
	public void testBase64()
    {
		boolean allOK = true;
		
		// create literal data packet
		System.out.println("Creating new LiteralDataPacket...");

		try
		{
			// todo create packet
			LiteralDataPacket p = new LiteralDataPacket(format, filename, rawdata.getBytes());
	
			// encode and write out
			System.out.println("Writing packet to file...");
			System.out.println("  Opening packet stream to "+outputfile+"...");
			FileOutputStream stream = new FileOutputStream(outputfile);
			
			System.out.println("  Encoding and writing packet...");
			stream.write(Base64.encode(p.encodePacket()));
			
			System.out.println("  Closing stream...");
			stream.close();
	
			// read in
			System.out.println("Reading packet from file...");
			System.out.println("  Opening packet stream to "+outputfile+"...");
			FileInputStream instream = new FileInputStream(outputfile);
			ByteArrayOutputStream bout = new ByteArrayOutputStream();
			
			System.out.println("  Reading packet...");
			int b = 0;
			while ((b = instream.read())!=-1) 
				bout.write(b);
	
			System.out.println("  Closing stream...");
			instream.close();
	
			// decode
			System.out.println("Decoding...");
			byte decoded[] = Base64.decode(bout.toByteArray());
	
			// construct packet
			System.out.println("Constructing packet...");
			System.out.println("  Opening packet stream...");
			OpenPGPPacketInputStream instream2 = new OpenPGPPacketInputStream(new ByteArrayInputStream(decoded));
			
			System.out.println("  Reading packet...");
			Packet p2 = instream2.readPacket();
			
			System.out.println("  Closing stream...");
			instream2.close();
	
			// compare
			System.out.println("Comparing...");
			
			LiteralDataPacket lp = (LiteralDataPacket)p2;
			
			// format
			System.out.print("  Format... ");
			if (lp.getFormat()==format) 
			{
				// ok
				System.out.println("Ok");
			} 
			else 
			{
				// error
				System.out.print(lp.getFormat());
				System.out.println("...Error!");
				allOK = false;
			}
	
			// Filename
			System.out.print("  Filename... ");
			if (lp.getFilename().compareTo(filename)==0) 
			{
				// ok
				System.out.println("Ok");
			} 
			else 
			{
				// error
				System.out.print(lp.getFilename());
				System.out.println("Error!");
				allOK = false;
			}
	
			// data only
			System.out.print("  Data... ");
			if (new String(lp.getData()).compareTo(rawdata)==0) 
			{
				// ok
				System.out.println("Ok");
			} 
			else 
			{
				// error
				System.out.println("Error!");
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
		
		// tell JUnit the results of the test
        assertTrue( allOK );
    }
    
}
