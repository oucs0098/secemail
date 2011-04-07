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

package core.protocolhandlers;
import core.interfaces.RecvPipeServerInterface;
import core.interfaces.RecvPipeClientInterface;
import core.iptp.*;
import core.exceptions.*;
import java.net.*;
import java.io.*;
import java.util.*;

/**
 * <p>POP3 Protocol handler.</p>
 * <p>This class is used with the IncomingEmailPipe to provide translation to and from the POP3 protocol.</p>
 * <p>Implements IPTP v1</p>
 * @see core.IncomingEmailPipe
 */
public class POP3Handler extends ProtocolHandler implements RecvPipeServerInterface, RecvPipeClientInterface {

   /**
     * <p>Awaits a command from the client.</p>
     * <p>This currently only maps selective commands (email transfer etc), otherwise the transaction is just relayed. See the Proxy Protocol
     * paper for details.</p>
     * <p>You MUST throw a NoMappingPossibleException if no mapping is possible (only really applicable in possible later versions
     * of the Proxy Protocol where full mapping is attempted).</p>
     * @throws NoMappingPossibleException if no mapping is possible (future enhancement, see protocol spec).
     * @throws PipeCommunicationException if there was a general communication problem.
     */
    public IPTPCommand awaitCommand() throws NoMappingPossibleException, PipeCommunicationException {

        IPTPCommand command = null;

        // read string from client
        String rawcommandstring = awaitRawCommandLine();
        rawcommandstring += "\r\n";

        // tokenize to obtain command
        StringTokenizer st = new StringTokenizer(rawcommandstring,"\n\r -");
        int numTokens = st.countTokens();
        Vector tokens = new Vector();
        while (st.hasMoreTokens()) {
            tokens.add(st.nextToken());
        }

        // match command
        String rawcommand = (String)tokens.elementAt(0);

        if(rawcommand.compareToIgnoreCase("user")==0) {
            if (numTokens>1) {
                command = new IPTPUser((String)tokens.elementAt(1));
            }
            else {
                command = new IPTPUser("");
            }
        }
        else if(rawcommand.compareToIgnoreCase("pass")==0) {
            if (numTokens>1) {
                command = new IPTPPass((String)tokens.elementAt(1));
            }
            else {
                command = new IPTPPass("");
            }
        }
        else if(rawcommand.compareToIgnoreCase("retr")==0) {
            if (numTokens>1) {
                command = new IPTPRetr(Integer.parseInt((String)tokens.elementAt(1)));
            }
            else {
                command = new IPTPRetr(0);
            }
        }
        else if(rawcommand.compareToIgnoreCase("list")==0) {
            if (numTokens>1) {
                command = new IPTPList(Integer.parseInt((String)tokens.elementAt(1)));
            }
            else {
                command = new IPTPList();
            }
        }
        else if(rawcommand.compareToIgnoreCase("uidl")==0) {
            if (numTokens>1) {
                command = new IPTPUidl(Integer.parseInt((String)tokens.elementAt(1)));
            }
            else {
                command = new IPTPUidl();
            }
        }
        else if(rawcommand.compareToIgnoreCase("capa")==0) {
            // request a list of capabilities from the server (rfc 2449)
        	command = new IPTPCapabilities();
        }
        else if (rawcommand.compareToIgnoreCase("quit")==0) {
            // Tell the proxy server that mail transfer is about to begin
            command = new IPTPQuit();
        }
        else {
            // relay everything else
            command = new IPTPRelay(rawcommandstring);
        }

        return command;
    }

    /**
     * <p>Await a command response from the email server after sending a command.</p>
     * <p>This currently only maps selective commands (email transfer etc), otherwise the transaction is just relayed. See the Proxy Protocol
     * paper for details.</p>
     * <p>You MUST throw a NoMappingPossibleException if no mapping is possible (only really applicable in possible later versions
     * of the Proxy Protocol where full mapping is attempted).</p>
     * @throws NoMappingPossibleException if no mapping is possible (future enhancement, see protocol spec).
     * @throws PipeCommunicationException if there was a general communication problem.
     */
    public IPTPCommandResponse awaitCommandResponse() throws NoMappingPossibleException, PipeCommunicationException {

        IPTPCommandResponse commandresponse = null;

        // read incoming data and obtain whether this should read more than one line (a bit of a hack)
        String rawcommandresponsestring = awaitRawCommandResponseLine();
        rawcommandresponsestring += "\r\n";

        // tokenize the initial/only line received to obtain command
        StringTokenizer st = new StringTokenizer(rawcommandresponsestring,"\n\r ");
        int numTokens = st.countTokens();
        Vector tokens = new Vector();
        while (st.hasMoreTokens()) {
            tokens.add(st.nextToken());
        }

        // match command
        String rawcommandresponse = (String)tokens.elementAt(0);

        // test whether we have to read multiple lines. In POP3 only +ve results can be multiline
        if (rawcommandresponse.compareToIgnoreCase("+OK")==0) {
            if ((lastCommandToServer!=null) && (lastCommandToServer.isExpectingMultilineResponse())) {
                // expecting multiline response
                StringBuffer buffer = new StringBuffer();
                buffer.append(rawcommandresponsestring);

                do {
                    rawcommandresponsestring = awaitRawCommandResponseLine();
                    buffer.append(rawcommandresponsestring);
                    buffer.append("\r\n");
                } while (rawcommandresponsestring.compareToIgnoreCase(".")!=0);

                rawcommandresponsestring = buffer.toString();
            }
        }
        
        // construct command
        if (lastCommandToServer instanceof IPTPUser) {
            // test if command was ok or not
            if (rawcommandresponse.compareToIgnoreCase("+OK")==0) {
                // ok
                commandresponse = new IPTPUserResponse(true);
            }
            else {
                // not
                commandresponse = new IPTPUserResponse(false);
            }
        }
        else if(lastCommandToServer instanceof IPTPPass) {
            // test if command was ok or not
            if (rawcommandresponse.compareToIgnoreCase("+OK")==0) {
                // ok
                commandresponse = new IPTPPassResponse(true);
            }
            else {
                // not
                commandresponse = new IPTPPassResponse(false);
            }
        }
        else if(lastCommandToServer instanceof IPTPRetr) {
            // test if command was ok or not
            if (rawcommandresponse.compareToIgnoreCase("+OK")==0) {
                String message;

                // ok
                try {
                    message = rawcommandresponsestring.substring(rawcommandresponsestring.indexOf("\r\n")+2, rawcommandresponsestring.indexOf("\r\n.\r\n"));
                } catch (IndexOutOfBoundsException e) {
                    message = "";
                }

                commandresponse = new IPTPRetrResponse(true, message);
            }
            else {
                // not
                commandresponse = new IPTPRetrResponse(false, "");
            }
        }
        else if (lastCommandToServer instanceof IPTPList) {
            IPTPList c = (IPTPList)lastCommandToServer;
            if (rawcommandresponse.compareToIgnoreCase("+OK")==0) {
                if (c.isExpectingMultilineResponse()) {
                	if (rawcommandresponsestring.indexOf("\r\n") == rawcommandresponsestring.indexOf("\r\n.\r\n")) { // empty multiline response
                		commandresponse = new IPTPListResponse(true);
                	} else {
                		commandresponse = new IPTPListResponse(true, rawcommandresponsestring.substring(rawcommandresponsestring.indexOf("\r\n")+2, rawcommandresponsestring.indexOf("\r\n.\r\n")));
                	}
                }
                else {
                    commandresponse = new IPTPListResponse(true, rawcommandresponsestring.substring(rawcommandresponsestring.indexOf(" ")+1, rawcommandresponsestring.indexOf("\r\n")));
                }
            }
            else {
                // not
                commandresponse = new IPTPListResponse(false);
            }
        }
        else if (lastCommandToServer instanceof IPTPUidl) {
            IPTPUidl c = (IPTPUidl)lastCommandToServer;
            if (rawcommandresponse.compareToIgnoreCase("+OK")==0) {
                if (c.isExpectingMultilineResponse()) {
                	if (rawcommandresponsestring.indexOf("\r\n") == rawcommandresponsestring.indexOf("\r\n.\r\n")) { // empty multiline response
                		commandresponse = new IPTPUidlResponse(true);
                	} else {
                		commandresponse = new IPTPUidlResponse(true, rawcommandresponsestring.substring(rawcommandresponsestring.indexOf("\r\n")+2, rawcommandresponsestring.indexOf("\r\n.\r\n")));
                	}
                }
                else {
                    commandresponse = new IPTPUidlResponse(true, rawcommandresponsestring.substring(rawcommandresponsestring.indexOf(" ")+1, rawcommandresponsestring.indexOf("\r\n")));
                }
            }
            else {
                // not
                commandresponse = new IPTPUidlResponse(false);
            }
        }
        else if (lastCommandToServer instanceof IPTPCapabilities) {
        	IPTPCapabilities c = (IPTPCapabilities)lastCommandToServer;
            if (rawcommandresponse.compareToIgnoreCase("+OK")==0) {
                if (c.isExpectingMultilineResponse()) {
                	if (rawcommandresponsestring.indexOf("\r\n") == rawcommandresponsestring.indexOf("\r\n.\r\n")) { // empty multiline response
                		commandresponse = new IPTPCapabilitiesResponse(true);
                	} else {
                		commandresponse = new IPTPCapabilitiesResponse(true, rawcommandresponsestring.substring(rawcommandresponsestring.indexOf("\r\n")+2, rawcommandresponsestring.indexOf("\r\n.\r\n")));
                	}
                }
                else {
                    commandresponse = new IPTPCapabilitiesResponse(true, rawcommandresponsestring.substring(rawcommandresponsestring.indexOf(" ")+1, rawcommandresponsestring.indexOf("\r\n")));
                }
            }
            else {
                // not
                commandresponse = new IPTPCapabilitiesResponse(false);
            }
        }
        else if(lastCommandToServer instanceof IPTPQuit) {
            // quit response
            // test if command was ok or not
            if (rawcommandresponse.compareToIgnoreCase("+OK")==0) {
                // ok
                commandresponse = new IPTPQuitResponse(true);
            }
            else {
                // not
                commandresponse = new IPTPQuitResponse(false);
            }
        }
        else {
            if (rawcommandresponse.compareToIgnoreCase("+OK")==0) {
                commandresponse = new IPTPRelayResponse(true, rawcommandresponsestring);
            }
            else {
                commandresponse = new IPTPRelayResponse(false, rawcommandresponsestring);
            }
        }

        return commandresponse;
    }

    /**
     * <p>Send a command to the email server.</p>
     * <p>This currently only maps selective commands (email transfer etc), otherwise the transaction is just relayed. See the Proxy Protocol
     * paper for details.</p>
     * <p>You MUST throw a NoMappingPossibleException if no mapping is possible (only really applicable in possible later versions
     * of the Proxy Protocol where full mapping is attempted).</p>
     * @param command The internal proxy protocol command, together with any parameters.
     * @throws NoMappingPossibleException if no mapping is possible (future enhancement, see protocol spec).
     * @throws PipeCommunicationException if there was a general communication problem.
     */
    public void sendCommand(IPTPCommand command) throws NoMappingPossibleException, PipeCommunicationException {

        lastCommandToServer = command;

        if (command instanceof IPTPUser) {
            IPTPUser c = (IPTPUser)command;
            sendRawCommand("USER " + c.getUserID() + "\r\n");
        }
        else if (command instanceof IPTPPass) {
            IPTPPass c = (IPTPPass)command;
            sendRawCommand("PASS " + c.getPasscode() + "\r\n");
        }
        else if (command instanceof IPTPRetr) {
            IPTPRetr c = (IPTPRetr)command;
            sendRawCommand("RETR " + c.getMessageNo() + "\r\n");
        }
        else if (command instanceof IPTPList) {
            IPTPList c = (IPTPList)command;
            if (c.getMessageNo() >= 0)
                sendRawCommand("LIST " + c.getMessageNo() + "\r\n");
            else
                sendRawCommand("LIST\r\n");
        }
        else if (command instanceof IPTPUidl) {
            IPTPUidl c = (IPTPUidl)command;
            if (c.getMessageNo() >= 0)
                sendRawCommand("UIDL " + c.getMessageNo() + "\r\n");
            else
                sendRawCommand("UIDL\r\n");
        }
        else if (command instanceof IPTPCapabilities) {
        	sendRawCommand("CAPA\r\n");
        }
        else if(command instanceof IPTPQuit) {
            sendRawCommand("QUIT\r\n");
        }
        else if (command instanceof IPTPRelay) {
            IPTPRelay c = (IPTPRelay)command;
            sendRawCommand(c.getRelay());
        }
    }

    /**
     * <p>Send a command response back to the client.</p>
     * <p>This currently only maps selective commands (email transfer etc), otherwise the transaction is just relayed. See the Proxy Protocol
     * paper for details.</p>
     * <p>You MUST throw a NoMappingPossibleException if no mapping is possible (only really applicable in possible later versions
     * of the Proxy Protocol where full mapping is attempted).</p>
     * @throws NoMappingPossibleException if no mapping is possible (future enhancement, see protocol spec).
     * @throws PipeCommunicationException if there was a general communication problem.
     */
    public void sendCommandResponse(IPTPCommandResponse commandResponse) throws NoMappingPossibleException, PipeCommunicationException {

        if (commandResponse instanceof IPTPUserResponse) {
            if (commandResponse.isOk()) {
                // ok
                sendRawCommandResponse("+OK User accepted by server. \r\n");
            }
            else {
                // error
                sendRawCommandResponse("-ERR User not accepted. \r\n");
            }
        }
        else if (commandResponse instanceof IPTPPassResponse) {
            if (commandResponse.isOk()) {
                // ok
                sendRawCommandResponse("+OK Passcode accepted by server. \r\n");
            }
            else {
                // error
                sendRawCommandResponse("-ERR Passcode not accepted. \r\n");
            }
        }
        else if (commandResponse instanceof IPTPRetrResponse) {
            if (commandResponse.isOk()) {
                // ok
                IPTPRetrResponse r = (IPTPRetrResponse)commandResponse;
                //sendRawCommandResponse("+OK " + String.valueOf(r.getSize()) + " octets\r\n" + r.getMessage());
                sendRawCommandResponse("+OK Message follows.\r\n" + r.getMessage() + "\r\n.\r\n");
            }
            else {
                // error
                sendRawCommandResponse("-ERR No such message. \r\n");
            }
        }
        else if (commandResponse instanceof IPTPListResponse) {
            if (commandResponse.isOk()) {
                // ok
                IPTPListResponse r = (IPTPListResponse)commandResponse;
                IPTPList c = (IPTPList)lastCommandToServer;
                if (c.isExpectingMultilineResponse()) {
                    // multiline
                	if (r.getScanlisting().length() == 0) { // avoid blank lines
                		sendRawCommandResponse("+OK Scan listing follows.\r\n.\r\n");
                	} else {
                		sendRawCommandResponse("+OK Scan listing follows.\r\n" + r.getScanlisting() + "\r\n.\r\n"); 
                	}
                }
                else {
					// single line
                    sendRawCommandResponse("+OK " + r.getScanlisting() + "\r\n");
                }

            }
            else {
                // error
                sendRawCommandResponse("-ERR No such message. \r\n");
            }
        }
        else if (commandResponse instanceof IPTPUidlResponse) {
            if (commandResponse.isOk()) {
                // ok
                IPTPUidlResponse r = (IPTPUidlResponse)commandResponse;
                IPTPUidl c = (IPTPUidl)lastCommandToServer;
                if (c.isExpectingMultilineResponse()) {
                    // multiline
                	if (r.getScanlisting().length() == 0) { // avoid blank lines
                		sendRawCommandResponse("+OK\r\n.\r\n");
                	} else {
                    	sendRawCommandResponse("+OK\r\n" + r.getScanlisting() + "\r\n.\r\n"); 
                    }
                }
                else {
                    // single line
                    sendRawCommandResponse("+OK " + r.getScanlisting() + "\r\n");
                }

            }
            else {
                // error
                sendRawCommandResponse("-ERR No such message. \r\n");
            }
        }
        else if (commandResponse instanceof IPTPCapabilitiesResponse) {
            if (commandResponse.isOk()) {
                // ok
            	IPTPCapabilitiesResponse r = (IPTPCapabilitiesResponse)commandResponse;
            	IPTPCapabilities c = (IPTPCapabilities)lastCommandToServer;
                if (c.isExpectingMultilineResponse()) {
                    // multiline
                	if (r.getScanListing().length() == 0) { // avoid blank lines
                		sendRawCommandResponse("+OK\r\n.\r\n"); 
                	} else {
                		sendRawCommandResponse("+OK\r\n" + r.getScanListing() + "\r\n.\r\n"); 
                	}
                }
                else {
                    // single line
                    sendRawCommandResponse("+OK " + r.getScanListing() + "\r\n");
                }

            }
            else {
                // error
                sendRawCommandResponse("-ERR There was a problem. \r\n");
            }
        }
        else if (commandResponse instanceof IPTPQuitResponse) {
            if (commandResponse.isOk()) {
                // ok
                sendRawCommandResponse("+OK Ta ta.\r\n");
            }
            else {
                // error
                sendRawCommandResponse("-ERR There was a problem. \r\n");
            }
        }
        else if (commandResponse instanceof IPTPRelayResponse) {
            IPTPRelayResponse cr = (IPTPRelayResponse)commandResponse;
            sendRawCommandResponse(cr.getRelay());
        }
    }
}
