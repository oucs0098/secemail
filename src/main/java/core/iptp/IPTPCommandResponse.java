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

package core.iptp;

/**
 * <p>Superclass for all IPTP Command responses.</p>
 * <p>This class provides the base implementation of a success status response. Children of this class extend
 * the command to include more information as needed.</p>
 * <p>Your protocol handler will have to maintain some context information (the last command sent to the mail server)
 * in order to respond with the correct command response class. This is necessary because involved protocols like SMTP
 * have different codes for success and fail depending on the last command that was issued to the server.</p>
 */
public abstract class IPTPCommandResponse extends IPTP {

    /** Was the last command (command that this is responding to) successful or not? */
    private boolean success;
    
    public IPTPCommandResponse() {
    }
    
    /** Creates a new instance of IPTPCommandResponse 
     * @param ok Was the last command (command that this is responding to) successful or not?
     */
    public IPTPCommandResponse(boolean isok) {
        setOk(isok);
    }

    /** Returns true if the last command (command that this is responding to) was successful. 
     * @see #setOk(boolean)
     */
    public boolean isOk() {
        return success;
    }
    
    /** Set the flag denoting whether the last command (command that this is responding to) was successful or not. 
     * @see #isOk()
     */
    protected void setOk(boolean suc) {
        success = suc;
    }
    
}
