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

import core.email.*;
import junit.framework.TestCase;
import java.io.*;

/**
 * <p>A class that tests the key functions of the Email class - header, body extraction / construction & attach handling.</p>
 * <p>for each test, read in & print info, write out attachment, construct new email with body + attachments, modify a header + add a header.</p>
 */
public class TestEmailClass extends TestCase {
    
    public final String emailfile1 = "/testdata/EmailClassTest1.eml";
    public final String emailfile2 = "/testdata/EmailClassTest2.eml";
    public final String emailfile3 = "/testdata/EmailClassTest3.eml";
    public final String emailfile4 = "/testdata/EmailClassTest4.eml";
    public final String emailfile5 = "/testdata/EmailClassTest5.eml";
    
    private boolean processFile(String file, String outfile)
    {
    	boolean allOK = true;
    	
    	try
    	{
			// Retrieve resource
			InputStream in = getClass().getResourceAsStream( file );
			//FileInputStream in = new FileInputStream(file);
			byte [] email1_dat = new byte[in.available()];
			in.read(email1_dat);
			in.close();
			
			System.out.println("Parsing...");
			Email email1 = new Email(email1_dat);
			
			System.out.println("Analysing...");
			
			if (email1.isMultipartBody())
			    System.out.println("Email has a MULTIPART body");
			
			EmailHeader [] e = email1.getHeader("from");
			System.out.println("Email is from : "+ e[0].getTagValue());
			e = email1.getHeader("to");
			System.out.println("Email is to : "+ e[0].getTagValue());
			e = email1.getHeader("subject");
			System.out.println("Email subject is : "+ e[0].getTagValue());
			EmailHeader [] headers1 = email1.getHeaderArray();
			
			System.out.println("Reading recipients using a different method : ");
			String [] to = email1.getRecipients();
			for (int n=0; n<to.length; n++) 
			    System.out.println(to[n]);
			
			System.out.println("Full headers are....");
			for (int n = 0; n < headers1.length; n++) 
			    System.out.println("-- " + headers1[n].toString());
			
			EmailAttachment [] attachments = email1.getAttachments();
			if (attachments!=null) {
			    System.out.println("Email has the following attachments...");    
			    for (int n = 0; n < attachments.length; n++)
			        System.out.println("File : " + attachments[n].getFilename());
			    }
			
			System.out.println("Modifying subject...");    
			email1.setHeader("subject", "This is a modified subject header for email 1");
			System.out.println("Adding a new header...");    
			email1.setHeader("foo", "This is an extra tag");
			
			e = email1.getHeader("subject");
			System.out.println("Email subject is now : "+ e[0].getTagValue());
			e = email1.getHeader("foo");
			System.out.println("Foo is : "+ e[0].getTagValue());
			  
			System.out.println("Writing email out again...");
			FileOutputStream out = new FileOutputStream(outfile);
			out.write(email1.getBytes());
			out.close();
    	}
    	catch( Exception e )
    	{
    		e.printStackTrace();
    		allOK = false;
    	}
    	
    	return allOK;
    }
    
    /*
     * Test a normal email
     */
    public void testNormalEmail()
    {
    	assertTrue( processFile(emailfile1, "email-1.eml") );
    }
    
    /*
     * Test an email made up of 2 attachments
     */
    public void test2AttachmentsEmail()
    {
    	assertTrue( processFile(emailfile2, "email-2.eml") );
    }
    
    /*
     * Test an email made up of 3 attachments
     */
    public void test3AttachmentsEmail()
    {
    	assertTrue( processFile(emailfile3, "email-3.eml") );
    }
    
    /*
     * Test an RTF, with attachment, email
     */
    public void testRTFWithAttachmentEmail()
    {
    	assertTrue( processFile(emailfile4, "email-4.eml") );
    }
    
    /*
     * Test an RTF, without attachment, email
     */
    public void testRTFWithoutAttachmentEmail()
    {
    	assertTrue( processFile(emailfile5, "email-5.eml") );
    }
    
}
