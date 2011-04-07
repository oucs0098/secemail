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

package core.email.util;
import core.exceptions.*;
import core.email.*;
import java.lang.IndexOutOfBoundsException;
import java.lang.String;
import java.io.*;

/**
 * <p>A class containing various mail parser tools.</p>
 */
public class MailParserTools {
    
    /** Creates a new instance of MailParserTools */
    public MailParserTools() {
    }
    
    /** 
     * <p>Extract MIME boundary information.</p>
     * <p>Extracts the mime boundary from the given header.</p>
     * @param head[] An array of EmailHeader containing the email header information.
     * @return the boundary string or null if no content-type tag found.
     * @throws EmailDataFormatException if the mime header was badly formatted.
     */
    public static String getBoundary(EmailHeader [] head) throws EmailDataFormatException {
        String boundary = null;
        
        EmailHeader bheader = null;
        for (int n = 0; n < head.length; n++)
            if (head[n].getTagName().compareToIgnoreCase("content-type")==0) {
                bheader = head[n];
                break;
            }
        
        //EmailHeader [] bheader = getHeader("content-type"); 
        if (bheader == null)
            return null;

        try {
            String contenttype = bheader.getTagValue();
            if (contenttype.indexOf("boundary=\"")!= -1) {
                boundary = contenttype.substring(contenttype.indexOf("boundary=\"")+10);
                boundary = boundary.substring(0, boundary.indexOf("\""));
            }
        } catch (IndexOutOfBoundsException i) {
            throw new EmailDataFormatException("Email has a badly formatted MIME header!");
        }
        
        return boundary;
    }

}
