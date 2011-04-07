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

/**
 * <p>Identify an OpenPGP key by 8byte KeyID.</p>
 * <p>With this key the getDefaultID() method will return the 8 byte KeyID.</p>
 */
public class OpenPGPKeyIDKeyIdentifier implements KeyIdentifier {
    
    /** Key ID */
    private byte keyid[];
    
    /** Creates a new instance of OpenPGPKeyIDKeyIdentifier.
     * @param id[] the 8 byte key ID being looked for.
     * @throws KeyHandlerException if the key id provided is the wrong length.
     */
    public OpenPGPKeyIDKeyIdentifier(byte id[]) throws KeyHandlerException {
        if (id.length!=8)
            throw new KeyHandlerException("Key ID is not 8 bytes long!");
        
        keyid = id;
    }
    
    /**
     * <p>Return the default identifier for a key ID.</p>
     * <p>This method is defined here so that all KeyIdentifier classes and children have
     * some common way of identifying a key. </p>
     * <p>What this method actually returns is of course implementation specific.</p>
     * @throws KeyHandlerException if something went wrong.
     */
    public byte[] getDefaultID() throws KeyHandlerException {
        return keyid;
    }
    
}
