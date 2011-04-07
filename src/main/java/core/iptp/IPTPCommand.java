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
import java.lang.*;

/**
 * <p>Superclass for all IPTP Command.</p>
 * <p>This class provides the base implementation of an IPTP command. Children of this class extend
 * the command to include more information as needed.</p>
 * <p>It is up to your protocol handler to create and decode the internal commands to and from the 
 * native protocol (SMTP etc).</p>
 */
public abstract class IPTPCommand extends IPTP {
    
    /** Flag that tells the protocol handlers that this command expects a multiline response. */
    private boolean expectsMultilineResponse;
    
    /** Default constructor, sets multiline to false.*/
    public IPTPCommand() {
        setExpectingMultilineResponse(false);
    }
    
    /** <p>Set the multiline flag.</p>
     * <p>This can be used by the protocol handlers to test whether the command expects a 
     * multiple line response from the server.</p>
     * <p>I confess this is a bit of a hack, I'll think of something better in a later version.</p>
     * @see #isExpectingMultilineResponse()
     */
    protected void setExpectingMultilineResponse(boolean multiline) {
        expectsMultilineResponse = multiline;
    }
    
    /** <p>Get the status of the multiline flag.</p>
     * @see #setExpectingMultilineResponse(boolean)
     */
    public boolean isExpectingMultilineResponse() {
        return expectsMultilineResponse;
    }
}
