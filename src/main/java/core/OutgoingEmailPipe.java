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

package core;
import core.iptp.*;
import core.interfaces.*;
import core.exceptions.*;
import core.protocolhandlers.*;
import core.algorithmhandlers.*;
import core.keyhandlers.*;
import core.email.*;
import java.lang.*;
import java.io.*;
import java.net.*;
import java.security.PrivateKey;
import javax.swing.JOptionPane;

/**
 * <p>The OutgoingEmailPipe class presents a server to a user's email client, and then connects
 * to a remote server and negotiates the transfer of email to the server from the client.</p>
 *
 * <p>A pipe is constructed out of components that act on a an email message. The ends of the
 * pipe are constructed with objects implementing the SendPipeClientInterface (on the end of the pipe facing
 * the email server) and SendPipeServerInterface (on the end of the pipe facing the user's email client)
 * interfaces.</p>
 *
 * <p>These pipe ends convert the exchange between the client and server to and from the standard
 * internet protocols (eg SMTP) and a proxy server native protocol. This conversion allows the proxy to better
 * watch the exchange, allows a developer to extend the proxy server to support additional protocols.</p>
 *
 * <p>Essentially, the pipe relays the transaction between the client and server until it sees the email exchange begin.
 * Once the email begins, the email is intercepted and passed to the other objects in the pipe. The email is then relayed
 * with the appropriate change to the email size information.</p>
 *
 * <p>For security, and if the option has been activated, the pipe will require user authentication before it 
 * will connect to the mail server. This is to prevent other users on the same machine from sending email through the proxy
 * by accident or on purpose.</p>
 *
 * <p>The outgoing message has some extra information (proxy version number etc) added to the header. This is done
 * purely for information gathering purposes and is not strictly necessary.</p>
 *
 * @see SendPipeServerInterface
 * @see AlgorithmHandler
 * @see SendPipeClientInterface
 */
public class OutgoingEmailPipe extends EmailPipe
{
        /** The object that handles connections from the email client. */
        protected SendPipeServerInterface protocolServer;
        /** The object that handles connections to the email server. */
        protected SendPipeClientInterface protocolClient;
        
        /** The object that handles the passphrase requests */
        private PassPhraseRequester requester;

        /** Encrypt all outgoing mail? */
        private boolean encryptAll;

        /** Sign all outgoing mail? */
        private boolean signAll;
        
        /**
         * <p>Outgoing email pipe constructor. </p>
         * <p>A minimum implementation MUST provide valid not null values for protocolServerHandler and
         * protocolClientHandler.</p>
         * <p>An actually USEFUL implementation should also provide valid objects for the handlers.</p>
         * @param protocolServerHandler A client facing mail handler.
         * @param algorithmHandler An object that handles encryption / decryption & signing / verification.
         * @param secKeyHandlers[] A list of handlers to look for secret keys in. This list is in order of preference.
         * @param pubKeyHandlers[] A list of handlers to look for public keys in. This list is in order of preference.
         * @param protocolClientHandler A server facing mail handler.
         * @param encrypt Set to true if you want the pipe to try and encrypt all outgoing email.
         * @param sign Set to true if you want the pipe to sign all outgoing email.
         * @throws ProxyServerCoreException if either protocolServerHandler or protocolClientHandler are null.
         */
        public OutgoingEmailPipe(SendPipeServerInterface protocolServerHandler,
                                 AlgorithmHandler algorithmHandler,
                                 KeyHandler secKeyHandlers[],
                                 PassPhraseRequester requester,
                                 KeyHandler pubKeyHandlers[],
                                 SendPipeClientInterface protocolClientHandler,
                                 boolean encrypt,
                                 boolean sign) throws ProxyServerCoreException {

                                     super();
                                     setPipeStatusPrefix("OutgoingEmailPipe");

                                     if ( (protocolServerHandler == null) || (protocolClientHandler == null) )
                                         throw new ProxyServerCoreException("Pipe constructed with null protocol handlers");

                                     protocolServer = protocolServerHandler;
                                     algorithm = algorithmHandler;
                                     protocolClient = protocolClientHandler;

                                     secretKeyHandlers = secKeyHandlers;
                                     this.requester = requester;
                                     
                                     publicKeyHandlers = pubKeyHandlers;

                                     encryptAll = encrypt;
                                     signAll = sign;
        }

        /** <p>Stop the pipe.</p>
         * <p>Stops the email pipe. </p>
         * <p>When stopping the protocolServer object stopPipe will handle any exception generated as a result of the socket
         * being in an accept state.<p>
         */
        public void stopPipe() {
            setRunning(false);

            try {
                if (protocolServer!=null)
                    protocolServer.disconnectFromClient();
            }
            catch (ProxyServerCoreException e) {
                printErr("OutgoingEmailPipe.stopPipe() : " + e.getMessage());
            }

            try {
                if (protocolClient!=null)
                    protocolClient.disconnectFromServer();
            }
            catch (ProxyServerCoreException e) {
                printErr("OutgoingEmailPipe.stopPipe() : " + e.getMessage());
            }
        }

	/**
	 * <p>Princible run loop.</p>
	 *
	 * <p>Listens for client connection and negotiates transfer of email.</p>
	 */
	public void run()
	{
            setRunning(true); // The thread is now running

            while (getRunning()) {

                // Create an email object
                Email email = null;
                EmailEnvelope envelope = null;
                boolean decoupled = false; // if true sets the pipe to capture rather than relay mode

                try {
                    // Await connection
                    printStatus("Awaiting connection");
                    protocolServer.awaitConnection();
                    
                    // TODO:
                    // If proxy requires logon
                        // Fake login and authenticate user against registered details. check md5 hash
                            // if OK then continue and log into the server
                                // if server requires logon then send server auth info
                        //  else
                            // return fail with big song and dance
                    // else
                        // log on normally

                    // Connection accepted, try and connect to mail server
                    printStatus("Connecting to Email server...");
                    protocolClient.connect();
                    
                    // TODO:
                        // Prompt for passphrase if not already done so

                    // Process email transaction until either socket is disconnected
                    printStatus("Processing commands...");
                    while ((protocolClient.isConnectedToServer()) && (protocolServer.isConnectedToClient())) {

                        IPTPCommand outgoing = null;
                        IPTPCommandResponse incoming = null;

                        // await response from server
                        if (!decoupled) {
                            incoming = protocolClient.awaitCommandResponse();

                            // analyse response

                            // test for quit
                            if (incoming instanceof IPTPQuitResponse) {
                                protocolServer.sendCommandResponse(incoming);
                                protocolServer.disconnectFromClient();
                                protocolClient.disconnectFromServer();
                                break;
                            }

                            if (!incoming.isOk()){
                               printErr("Mail server reported an error, will try and continue.");
                            }

                            // send response to email client
                            protocolServer.sendCommandResponse(incoming);
                        }

                        // await command
                        outgoing = protocolServer.awaitCommand();

                        // analyse command, send command to email server
                        if (outgoing instanceof IPTPMail) {
                            // Mail capture begin .. transaction is decoupled and all command responses are faked.
                            decoupled = true;

                            printStatus("Capturing outgoing email...");

                            IPTPMail mailcommand = (IPTPMail)outgoing;

                            // Create an envelope
                            envelope = new EmailEnvelope();
                            envelope.setSender(mailcommand.getSender());

                            // acknowledge
                            protocolServer.sendCommandResponse(new IPTPMailResponse(true));
                        }
                        else if (outgoing instanceof IPTPRcpt) {
                            // Add a recipient
                            decoupled = true;
                            printStatus("Adding recipient...");

                            IPTPRcpt rcpt = (IPTPRcpt)outgoing;

                            envelope.addRecipient(rcpt.getRecipient());

                            // acknowledge
                            protocolServer.sendCommandResponse(new IPTPRcptResponse(true));
                        }
                        else if (outgoing instanceof IPTPData) {
                            // Client requested to send an email
                            decoupled = true;
                            printStatus("Processing email...");

                            // acknowledge and begin mail transfer
                            protocolServer.sendCommandResponse(new IPTPDataResponse(true));

                            // await data
                            printStatus("Receiving email from client...");
                            IPTPCommand data = protocolServer.awaitCommand();

                            if (data instanceof IPTPSendData) {
                                // construct email
                                IPTPSendData tmp = (IPTPSendData)data;
                                email = new Email(tmp.getMessageData().getBytes());
                                email.setHeader("X-SecEmailProxy-Version",core.CoreVersionInfo.version); // append some version information to the email header for the benifit of system admins



                                // do encryption / signing
                                if (algorithm!=null) {
                                    
                                    boolean retry;
                                    boolean doEncryption = encryptAll; 
                                    boolean doSign = signAll; 
                                    
                                    printStatus("Encrypting/Signing email...");
                                    
                                    do {

                                        retry = false;
                                        
                                        try {
                                            email = algorithm.processOutgoingMail(doEncryption, doSign, publicKeyHandlers, secretKeyHandlers, email, passPhrases);
                                        } catch (ChecksumFailureException cfe) {
                                            // todo : prompt for new passcode until correct or cancelled.    
                                            
                                            retry = true;
                                            
                                            PassPhraseResponse reply = requester.requestPassPhrase("Enter passphrase for signing key", cfe.getMessage());
                                            
                                            if (reply.getResponseCode()==PassPhraseResponse.ABORT) {
                                                // abort
                                                throw new ProxyServerCoreException("Mail transfer aborted by user");
                                            } else if (reply.getResponseCode()==PassPhraseResponse.SENDANYWAY) {
                                                // send message unsigned
                                                doSign = false;
                                            } else {
                                                // add passphrase to list
                                                if (reply.getPassPhrase()!=null) {
                                                    addPassphrase(new PassPhrase(reply.getPassPhrase()));
                                                }
                                                    
                                            }
   
                                        } catch (SecretKeyNotFoundException sknfe) {
                                            // Secret Key (signer key) not found

                                            retry = true;
                                            
                                            Object[] possibleValues = { "Abort sending message", "Send message unsigned", "Retry" };
                                            Object selectedValue = JOptionPane.showInputDialog(null, sknfe.getMessage(), "Signing key not found", JOptionPane.INFORMATION_MESSAGE, null, possibleValues, possibleValues[0]);

                                            if (selectedValue!=null) {
                                                String sv = (String)selectedValue;

                                                if (sv.compareTo(possibleValues[0].toString())==0) {
                                                    // abort
                                                    throw new ProxyServerCoreException("Mail transfer aborted by user");
                                                } else if (sv.compareTo(possibleValues[1].toString())==0) {
                                                    // send unsigned
                                                    doSign = false;
                                                } 
                                                
                                            } else {
                                                throw new ProxyServerCoreException("Mail transfer aborted by user");
                                            }
                                            
                                        } catch (PublicKeyNotFoundException pknfe) {
                                            // Public Key (recipient key) not found

                                            retry = true;
                                            
                                            Object[] possibleValues = { "Abort sending message", "Send message in clear text to all recipients (not recommended)", "Retry" };
                                            Object selectedValue = JOptionPane.showInputDialog(null, pknfe.getMessage(), "Recipient key not found", JOptionPane.INFORMATION_MESSAGE, null, possibleValues, possibleValues[0]);

                                            if (selectedValue!=null) {
                                                String sv = (String)selectedValue;
                                                
                                                if (sv.compareTo(possibleValues[0].toString())==0) {
                                                    // abort
                                                    throw new ProxyServerCoreException("Mail transfer aborted by user");
                                                } else if (sv.compareTo(possibleValues[1].toString())==0) {
                                                    // send in the clear to all recipients
                                                    doEncryption = false;
                                                } 
                                                
                                            } else {
                                                throw new ProxyServerCoreException("Mail transfer aborted by user");
                                            }
                                        }
                                        
                                    } while (retry);
                                }

                                
                                // Send email to mail server
                                    printStatus("Sending email to server...");

                                    // initiate transfer
                                    protocolClient.sendCommand(new IPTPMail(envelope.getSender()));
                                    if (!protocolClient.awaitCommandResponse().isOk())
                                        throw new ProxyServerCoreException("Mail server did not accept sender.");

                                    // recipients
                                    for (int n = 0; n < envelope.getNumberOfRecipients(); n++) {
                                        protocolClient.sendCommand(new IPTPRcpt(envelope.getRecipient(n)));
                                        if (!protocolClient.awaitCommandResponse().isOk())
                                            throw new ProxyServerCoreException("Mail server did not accept recipient.");
                                    }

                                    // data
                                    protocolClient.sendCommand(new IPTPData());
                                    if (!protocolClient.awaitCommandResponse().isOk())
                                        throw new ProxyServerCoreException("Mail server did not accept data send request.");

                                    // send data
                                    protocolClient.sendCommand(new IPTPSendData(new String(email.getBytes())));
                                    if (!protocolClient.awaitCommandResponse().isOk())
                                        throw new ProxyServerCoreException("Mail server did not accept email.");

                                // return final ok (if we got this far then we should be ok)
                                protocolServer.sendCommandResponse(new IPTPSendDataResponse(true));
                                printStatus("Email successfully sent to mail server.");
                            }
                            else {
                                // error
                                throw new ProxyServerCoreException("Was expecting email data, got a command.");
                            }

                        }
                        else {
                            // All other commands including RELAY, just relay for now

                            // anything other than certain commands recouple the server
                            decoupled = false;

                            // send command to server
                            protocolClient.sendCommand(outgoing);
                        }
                    }
                } catch (ProxyServerCoreException ce) {
                    ce.printStackTrace();
                    printErr(ce.getMessage());
                }

                // At least one socket has dropped, or an error has occurred, perform some cleanup and return to the beginning of the loop
                stopPipe(); // halt the pipe
                setRunning(true); // we don't actually want to stop the pipe at this stage, just close the sockets
                System.gc(); // now should be a good time to do a little bit of cleanup
            }
	}
}