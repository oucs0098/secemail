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
import core.exceptions.KeyHandlerException;

/**
 * <p>A root abstract interface defining the common behaviour of key ID classes.</p>
 * <p>The way a key is identified depends on the algorithm being used. KeyIdentifier classes
 * encapsulate these in a common class hierachy.</p>
 * <p>Implementing classes are free to extend the interface and provide more detailed information
 * but they must implement a getDefaultID method.</p>
 */
public abstract interface KeyIdentifier {
   
    /**
     * <p>Return the default identifier for a key ID.</p>
     * <p>This method is defined here so that all KeyIdentifier classes and children have 
     * some common way of identifying a key. </p>
     * <p>What this method actually returns is of course implementation specific.</p>
     * @throws KeyHandlerException if something went wrong.
     */
    public abstract byte [] getDefaultID() throws KeyHandlerException;
    
}
