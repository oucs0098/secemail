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

package core.keyhandlers;
import core.algorithmhandlers.keymaterial.*;
import core.exceptions.KeyHandlerException;

/**
 * <p>A class that encapsulates the key data returned by the KeyHandler classes.</p>
 * <p>This root class returns the minimum generic information necessary (the raw key material), the implementation 
 * specific children of this class return more detailed information.</p>
 * @see AsymmetricAlgorithmParameters
 */
public class KeyData implements KeyObject {
    
    /** The wrapped key material */
    private AsymmetricAlgorithmParameters keyData;
        
    /** Creates a new instance of KeyData 
     * @param key Key to wrap.
     */
    public KeyData(AsymmetricAlgorithmParameters keyMaterial) {
        setKey(keyMaterial);
    }
    
    /** Return the key that this object encapsulates. */
    public AsymmetricAlgorithmParameters getKey() {
        return keyData;
    }
    
    /** Wrap a key in this object. */
    protected void setKey(AsymmetricAlgorithmParameters keyMaterial) {
       keyData = keyMaterial;
    }
    
    /** Method satisfying the requirement of the KeyObject interface */
    public KeyData getKeyData() {
    	return this;
    }

}
