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
 * <p>Was the command accepted. See the protocol spec for caveats.</p>
 * <p>This is a bit of a kludge at the moment, scan listings are currently relayed with
 * no further analysis.</p>
 */
public class IPTPUidlResponse extends IPTPCommandResponse {
    
    /** The scan listing. */
    private String scanlisting;
    
    /** Creates a single line response to the message */
    public IPTPUidlResponse(boolean isok) {
        setOk(isok);
        setScanlisting("");
    }

    /** Creates a new instance of IPTPUidlResponse containing a scan listing
     * @param isok Was the command successful or not
     * @param scanlst The email scan listing
     */
    public IPTPUidlResponse(boolean isok, String scanlst) {
        setOk(isok);
        setScanlisting(scanlst);
    }

    /** Set the email message. */
    protected void setScanlisting(String scanlst) {
        scanlisting = new String(scanlst);
    }

    /** Get the email message. Returns "" if single line response, or multiline.*/
    public String getScanlisting() {
        return scanlisting;
    }
}
