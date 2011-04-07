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
import core.exceptions.*;
import core.iptp.*;
import core.interfaces.SendPipeServerInterface;
import core.interfaces.SendPipeClientInterface;
import java.net.*;
import java.io.*;
import java.util.*;

/**
 * <p>SMTP Protocol handler.</p>
 * <p>This class is used with the OutgoingEmailPipe to provide translation to and from the SMTP protocol.</p>
 * <p>Implements IPTP v1</p>
 * @see core.OutgoingEmailPipe
 */
public class SMTPHandler extends ProtocolHandler implements SendPipeServerInterface, SendPipeClientInterface {

    /** Used by await command to give the context of the issued command. */
    private IPTPCommandResponse lastCommandResponseToClient;

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
        StringTokenizer st = new StringTokenizer(rawcommandstring,"\n\r ");
        int numTokens = st.countTokens();
        Vector tokens = new Vector();
        while (st.hasMoreTokens()) {
            tokens.add(st.nextToken());
        }

        // match command
        String rawcommand = (String)tokens.elementAt(0);

        if(rawcommand.compareToIgnoreCase("mail")==0) {

            // Tell the proxy server that mail transfer is about to begin

            if (numTokens>1) {

                String address;

                // try and extract address, should work if address has been properly formatted
                try {
                    address = rawcommandstring.substring(rawcommandstring.indexOf("<")+1, rawcommandstring.indexOf(">"));
                } catch (IndexOutOfBoundsException e) {
                    address = "";
                }

                command = new IPTPMail(address);
            }
            else
                command = new IPTPMail("");
        }
        else if (rawcommand.compareToIgnoreCase("rcpt")==0) {
            // add a recipent
            if (numTokens>1) {

                String address;

                // try and extract address, should work if address has been properly formatted
                try {
                    address = rawcommandstring.substring(rawcommandstring.indexOf("<")+1, rawcommandstring.indexOf(">"));
                } catch (IndexOutOfBoundsException e) {
                    address = "";
                }

                command = new IPTPRcpt(address);
            }
            else
                command = new IPTPRcpt("");
        }
        else if (rawcommand.compareToIgnoreCase("data")==0) {
            // data request. See protocol spec for IPTPSendData caveats
            command = new IPTPData();
        }
        else if (rawcommand.compareToIgnoreCase("quit")==0) {
            // Tell the proxy server that mail transfer is about to begin
            command = new IPTPQuit();
        }
        else {
            if ((lastCommandResponseToClient instanceof IPTPDataResponse) && (lastCommandResponseToClient.isOk())) {
                // if the last response was a successful data send request then this SHOULD be the email data
                // read everything into a buffer and then parse result
                StringBuffer data = new StringBuffer();
                data.append(rawcommandstring);

                while ((rawcommandstring = awaitRawCommandLine()).compareToIgnoreCase(".")!=0) {
                    data.append(rawcommandstring);
                    data.append("\r\n");
                }

                command = new IPTPSendData(data.toString());
            }
            else {
                // relay everything else
                command = new IPTPRelay(rawcommandstring);
            }
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

        // read complete incoming response
        String tmp;
        StringBuffer buffer = new StringBuffer();
        do {
            tmp = awaitRawCommandResponseLine();
            buffer.append(tmp);
            buffer.append("\r\n");
        } while (tmp.charAt(3)!=' ');
        String rawcommandresponsestring = buffer.toString();

        // tokenize to obtain command
        StringTokenizer st = new StringTokenizer(rawcommandresponsestring,"\n\r -");
        int numTokens = st.countTokens();
        Vector tokens = new Vector();
        while (st.hasMoreTokens()) {
            tokens.add(st.nextToken());
        }

        // match command
        String rawcommandresponse = (String)tokens.elementAt(0);

        if (lastCommandToServer instanceof IPTPMail) {
            // mail repsonse, see if ok or not

            // test if command was ok or not
            if (rawcommandresponse.compareToIgnoreCase("250")==0) {
                // ok
                commandresponse = new IPTPMailResponse(true);
            }
            else {
                // not
                commandresponse = new IPTPMailResponse(false);
            }
        }
        else if(lastCommandToServer instanceof IPTPRcpt) {
            if ((rawcommandresponse.compareToIgnoreCase("250")==0) || (rawcommandresponse.compareToIgnoreCase("251")==0)) {
                // ok
                commandresponse = new IPTPRcptResponse(true);
            }
            else {
                // not
                commandresponse = new IPTPRcptResponse(false);
            }
        }
        else if(lastCommandToServer instanceof IPTPData) {
            // test if command was ok or not
            if (rawcommandresponse.compareToIgnoreCase("354")==0) {
                // ok
                commandresponse = new IPTPDataResponse(true);
            }
            else {
                // not
                commandresponse = new IPTPDataResponse(false);
            }
        }
        else if(lastCommandToServer instanceof IPTPSendData) {
            // test if command was ok or not
            if (rawcommandresponse.compareToIgnoreCase("250")==0) {
                // ok
                commandresponse = new IPTPSendDataResponse(true);
            }
            else {
                // not
                commandresponse = new IPTPSendDataResponse(false);
            }
        }
        else if(lastCommandToServer instanceof IPTPQuit) {
            // quit response

            // test if command was ok or not
            if (rawcommandresponse.compareToIgnoreCase("221")==0) {
                // ok
                commandresponse = new IPTPQuitResponse(true);
            }
            else {
                // not
                commandresponse = new IPTPQuitResponse(false);
            }
        }
        else {
            // relay everything else
            boolean success = false; // assume fail
            if (
                // if any of the success codes then set to true
                ("220".compareToIgnoreCase((String)rawcommandresponse)==0) ||
                ("250".compareToIgnoreCase((String)rawcommandresponse)==0) ||
                ("251".compareToIgnoreCase((String)rawcommandresponse)==0) ||
                ("354".compareToIgnoreCase((String)rawcommandresponse)==0) ||
                ("211".compareToIgnoreCase((String)rawcommandresponse)==0) ||
                ("214".compareToIgnoreCase((String)rawcommandresponse)==0) ||
                ("221".compareToIgnoreCase((String)rawcommandresponse)==0)
            )
                success = true;

            commandresponse = new IPTPRelayResponse(success, rawcommandresponsestring);
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

        if (command instanceof IPTPMail) {
            IPTPMail c = (IPTPMail)command;
            sendRawCommand("MAIL FROM:<" + c.getSender() + ">\r\n");
        }
        else if (command instanceof IPTPRcpt) {
            IPTPRcpt c = (IPTPRcpt)command;
            sendRawCommand("RCPT TO:<" + c.getRecipient() + ">\r\n");
        }
        else if (command instanceof IPTPData) {
            IPTPData c = (IPTPData)command;
            sendRawCommand("DATA\r\n");
        }
        else if (command instanceof IPTPSendData) {
            IPTPSendData c = (IPTPSendData)command;
            sendRawCommand(c.getMessageData() + "\r\n.\r\n");
        }
        else if(command instanceof IPTPQuit) {
            sendRawCommand("QUIT" + "\r\n");
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

        lastCommandResponseToClient = commandResponse;

        if (commandResponse instanceof IPTPMailResponse) {
            if (commandResponse.isOk()) {
                // ok
                sendRawCommandResponse("250 OK\r\n");
            }
            else {
                // error
                sendRawCommandResponse("500 Something went wrong\r\n");
            }
        }
        else if (commandResponse instanceof IPTPRcptResponse) {
            if (commandResponse.isOk()) {
                // ok
                sendRawCommandResponse("250 OK\r\n");
            }
            else {
                // error
                sendRawCommandResponse("500 Something went wrong\r\n");
            }
        }
        else if (commandResponse instanceof IPTPDataResponse) {
            if (commandResponse.isOk()) {
                // ok
                sendRawCommandResponse("354 OK, send data and terminate with <crlf>.<crlf>\r\n");
            }
            else {
                // error
                sendRawCommandResponse("554 Something went wrong\r\n");
            }
        }
        else if (commandResponse instanceof IPTPSendDataResponse) {
            if (commandResponse.isOk()) {
                // ok
                sendRawCommandResponse("250 OK\r\n");
            }
            else {
                // error
                sendRawCommandResponse("554 Something went wrong\r\n");
            }
        }
        else if(commandResponse instanceof IPTPQuitResponse) {
            if (commandResponse.isOk()) {
                // ok
                sendRawCommandResponse("221 Proxy is exiting\r\n");
            }
            else {
                // error
                sendRawCommandResponse("500 Proxy failed to quit\r\n");
            }
        }
        else if (commandResponse instanceof IPTPRelayResponse) {
            IPTPRelayResponse cr = (IPTPRelayResponse)commandResponse;
            sendRawCommandResponse(cr.getRelay());
        }
    }
}
