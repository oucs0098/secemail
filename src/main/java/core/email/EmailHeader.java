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

package core.email;
import java.lang.String;
import java.io.*;
import java.util.Vector;
import core.email.util.*;

/**
 * <p>A class encapsulating an email header entry in the format tag : value.</p>
 */
public class EmailHeader {
    
    /** Name of the tag */
    private String tagName;
    /** Value of tag */
    private String tagValue;
    
    /** Creates a new instance of EmailHeader */
    public EmailHeader(String tag, String value) {
        tagName = tag;
        tagValue = value;
    }
    
    /** Get the name of the tag. */
    public String getTagName() {
        return tagName;
    }
    
    /** Get the value of the tag. */
    public String getTagValue() {
        return tagValue;
    }
    
    /** Set the value of the tag. */
    public void setTagValue(String value) {
        tagValue = value;
    }
    
    /** Return the tag in the format "tag: tagvalue\r\n". */
    public String toString() {
        return getTagName() + ": " + getTagValue();
    }
    
    /** 
     * <p>Parse email headers.</p>
     * <p>Parses standard format email headers from an input stream returning them as an array
     * of EmailHeader.</p>
     * @param in the stream to read from, must be in the correct position.
     * @return an array of EmailHeader objects containing the parsed email headers in sequence or null if no headers were found before blank line or end of stream.
     */
    public static EmailHeader [] parseHeaders(InputStream in) throws IOException {
        Vector v = new Vector();
        
        String tmp = IOUtil.readLine(in);        
        while (tmp.length()>0) {

            StringBuffer sb = new StringBuffer();
            sb.append(tmp);              
            do {
                tmp = IOUtil.readLine(in);        
                if ((tmp.length()>0) && ((tmp.charAt(0)=='\t') || (tmp.charAt(0)==' ')) ) {//(tmp.charAt(0)=='\t')) {//((tmp.charAt(0)=='\t') || (tmp.charAt(0)==' ')) ) {
                    sb.append("\r\n");
                    sb.append(tmp); 
                }

            } while ((tmp.length()>0) && ((tmp.charAt(0)=='\t') || (tmp.charAt(0)==' ')) );//(tmp.charAt(0)=='\t')); //((tmp.charAt(0)=='\t') || (tmp.charAt(0)==' ')) );               

            // add line  
            try {
                String tag = sb.toString().substring(0,sb.toString().indexOf(": "));     
                String value = sb.toString().substring(sb.toString().indexOf(": ")+2);

                v.add(new EmailHeader(tag, value));
            } catch (StringIndexOutOfBoundsException sioobe) {
                // this isn't a valid header, so abort
                return null;
            }

        }
        
        EmailHeader [] heads = new EmailHeader[v.size()];
        for (int n = 0; n < v.size(); n++)
            heads[n] = (EmailHeader)v.elementAt(n);
        
        return heads;
    }
    
}
