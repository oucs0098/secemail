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
import java.util.*;

/**
 * <p>A class encapsulating an outgoing email.</p>
 * <p>The class encapsulates an email and stores SMTP routing information (To, From etc) in an easily
 * readable form for outgoing mail transfer.</p>
 */
public class EmailEnvelope {
    
    /** The sender. */
    private String reversepath;
    
    /** A list of recipients. */
    private Vector recipients;
    
    /** The email this object is wrapping. */
    private Email email;
    
    /** Creates a new instance of Envelope */
    public EmailEnvelope() {
        reversepath = null;
        recipients = new Vector();
        email = null;
    }
    
    /** Who is this email from (the return address). */
    public void setSender(String from) {
        reversepath = new String(from);
    }
    
    /** Get the envelope's reverse path (who is the sender). */
    public String getSender() {
        return reversepath;
    }
    
    /** Add a recipient */
    public void addRecipient(String rcpt) {
        recipients.addElement(rcpt);
    }
    
    /** How many recipients are there? */
    public int getNumberOfRecipients() {
        return recipients.size();
    }
    
    /** Return a given recipient */
    public String getRecipient(int rcpt) {
        return (String)recipients.elementAt(rcpt);
    }
    
    /** Return all recipients */
    public String [] getRecipients() {
        
        if (getNumberOfRecipients()>0) {
            String s [] = new String[getNumberOfRecipients()];
            for (int n = 0; n < s.length; n++)
                s[n] = getRecipient(n);

            return s;
        }
        
        return null;
    }
    
    /** Encapsulate an email. */
    public void wrapEmail(Email eml) {
        email = eml;
    }
    
    /** Return the current encapsulated email. */
    public Email getEmail() {
        return email;
    }

}
