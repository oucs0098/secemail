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

package core.keyhandlers.identifiers;
import core.keyhandlers.KeyIdentifier;
import core.exceptions.KeyHandlerException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.String;
import java.util.StringTokenizer;

/**
 * <p>Identify an OpenPGP key by username.</p>
 * <p>With this key the getDefaultID() method will return the "User Name <email@somewhere.com>" 
 * standard identifier.</p>
 */
public class OpenPGPStandardKeyIdentifier implements KeyIdentifier {
    
    /** Full name of user */
    private byte name[];
    
    /** The email address */
    private byte emailAddress[];
    
    /** Creates a new instance of OpenPGPKeyIdentifier. 
     * @param fullname[] The full name of the user, eg "Joe Bloggs", must not be null - if no name specified use "".
     * @param address[] The email address of the user (without brackets etc), eg "email@example.com".
     */
    public OpenPGPStandardKeyIdentifier(byte fullname[], byte address[]) {
        name = fullname;
        emailAddress = address;
    }
    
    /** <p>Creates a new instance of OpenPGPKeyIdentifier by attempting to parse an SMTP format 
     *  mail address eg "User Name <email@somewhere.com>".</p>
     * @param address The address to parse.
     * @throws KeyHandlerException if the email address could not be parsed.
     */
    public OpenPGPStandardKeyIdentifier(String address) throws KeyHandlerException {
        StringTokenizer str = new StringTokenizer(address, "<>\t\r\n\f");
        
        int tokens = str.countTokens();
        
        if (tokens==1) {
            // just email address
            name = "".getBytes();
            emailAddress = str.nextToken().getBytes();
        } else if (tokens==2) {
            // full email address with name
            
            String tmp = str.nextToken();
            
            // remove quotes from email address
            StringTokenizer str2 = new StringTokenizer(tmp, "\"\t\r\n\f");
            tmp = str2.nextToken();
            
            // clean up extra space in name
            if (tmp.charAt(tmp.length()-1)==' ')
                tmp = tmp.substring(0, tmp.length()-1);
            
            name = tmp.getBytes();
            emailAddress = str.nextToken().getBytes();
        } else {
            throw new KeyHandlerException("Could not parse address '"+address+"'");
        }
    }
    
    /**
     * Return the full name of the user.
     */
    public byte[] getName() {
        return name;
    }
    
    /** 
     * Return the email address.
     */
    public byte[] getEmailAddress() {
        return emailAddress;
    }
    
    /**
     * <p>Return the default identifier for a key ID.</p>
     * <p>This method is defined here so that all KeyIdentifier classes and children have
     * some common way of identifying a key. This class' children will have a richer
     * interface to return more detailed and specific information about a key.</p>
     * <p>What this method actually returns is of course implementation specific. In the case of
     * OpenPGP this would return the "User Name <email@somewhere.com>" standard identifier.</p>
     * @throws KeyHandlerException if something went wrong.
     */
    public byte[] getDefaultID() throws KeyHandlerException {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            
            if (getName().length>0) {
                out.write(getName());
                out.write(32); // " "
            }
            out.write(60); // "<"
            out.write(getEmailAddress());
            out.write(62); // ">"
            
            return out.toByteArray();
            
        } catch (IOException e) {
            throw new KeyHandlerException(e.getMessage());
        }
        
    }
    
}
