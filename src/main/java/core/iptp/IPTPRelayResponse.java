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
 * <p>Return a success code and the raw response from the server.</p>
 * <p>This is essentially a "misc" command for handling anything not handled specifically.</p>
 * <p>This will be depreciated in later IPTP releases in favour of mapping the internet protocol completely.</p>
 */
public class IPTPRelayResponse extends IPTPCommandResponse {
    
    /** The raw command response. */
    private String rawCommandResponse;
    
    /** Creates a new instance of IPTPRelayResponse 
     * @param isok Was the command successful.
     * @param rawcommand The raw command.
     */
    public IPTPRelayResponse(boolean isok, String rawcommandresponse) {
        setOk(isok);
        setRelay(rawcommandresponse);
    }
    
    /** Get the raw command response string. */
    public String getRelay() {
        return rawCommandResponse;
    }
    
    /** Set the raw command response string. */
    protected void setRelay(String rawcommandresponse) {
        rawCommandResponse = new String(rawcommandresponse);
    }
}
