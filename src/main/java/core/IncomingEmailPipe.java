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
import java.security.PrivateKey;
import java.lang.*;
import java.io.*;
import java.net.*;

/**
 * <p>The IncomingEmailPipe class presents a server to a user's email client, and then connects
 * to a remote server and negotiates the transfer of email from the server to the client.</p>
 *
 * <p>A pipe is constructed out of components that act on a an email message. The ends of the
 * pipe are constructed with objects implementing the RecvPipeClientInterface (on the end of the pipe facing
 * the email server) and RecvPipeServerInterface (on the end of the pipe facing the user's email client)
 * interfaces.</p>
 *
 * <p>These pipe ends convert the exchange between the client and server to and from the standard
 * internet protocols (eg POP3) and a proxy server native protocol. This conversion allows the proxy to better
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
 * @see RecvPipeServerInterface
 * @see AlgorithmHandler
 * @see RecvPipeClientInterface
 */
public class IncomingEmailPipe extends EmailPipe
{
        /** The object that handles connections from the email client. */
        protected RecvPipeServerInterface protocolServer;
        /** The object that handles connections to the email server. */
        protected RecvPipeClientInterface protocolClient;
        
        /** The object that handles the passphrase requests */
        private PassPhraseRequester requester;
        
        /**
         * <p>Incoming email pipe constructor. </p>
         * </p>A minimum implementation MUST provide valid not null values for protocolServerHandler and
         * protocolClientHandler.</p>
         * <p>An actually USEFUL implementation should also provide valid objects for the handlers.</p>
         * @param protocolServerHandler A client facing mail handler.
         * @param algorithmHandler An object that handles encryption / decryption & signing / verification.  
         * @param secKeyHandlers[] A list of handlers to look for secret keys in. This list is in order of preference.
         * @param pubKeyHandlers[] A list of handlers to look for public keys in. This list is in order of preference.
         * @param protocolClientHandler A server facing mail handler.
         * @throws ProxyServerCoreException if either protocolServerHandler or protocolClientHandler are null.
         */
        public IncomingEmailPipe(RecvPipeServerInterface protocolServerHandler,
                                 AlgorithmHandler algorithmHandler,
                                 KeyHandler secKeyHandlers[],
                                 PassPhraseRequester requester,
                                 KeyHandler pubKeyHandlers[],
                                 RecvPipeClientInterface protocolClientHandler) throws ProxyServerCoreException {

                                     super();
                                     setPipeStatusPrefix("IncomingEmailPipe");

                                     if ( (protocolServerHandler == null) || (protocolClientHandler == null) )
                                         throw new ProxyServerCoreException("Pipe constructed with null protocol handlers");

                                     protocolServer = protocolServerHandler;
                                     algorithm = algorithmHandler;
                                     protocolClient = protocolClientHandler;
                                     
                                     secretKeyHandlers = secKeyHandlers;
                                     this.requester = requester;
                                     
                                     publicKeyHandlers = pubKeyHandlers;
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
                printErr("IncomingEmailPipe.stopPipe() : " + e.getMessage());
            }

            try {
                if (protocolClient!=null)
                    protocolClient.disconnectFromServer();
            }
            catch (ProxyServerCoreException e) {
                printErr("IncomingEmailPipe.stopPipe() : " + e.getMessage());
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

                try {
                    // Await connection
                    printStatus("Awaiting connection");
                    protocolServer.awaitConnection();
                    
                    // TODO:
                    // If proxy requires logon
                        // Fake login and authenticate user against registered details. check md5 hash
                            // if OK then continue and log into the server
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

                        incoming = protocolClient.awaitCommandResponse();

                        // analyse response

                        if (!incoming.isOk()){
                           printErr("Mail server reported an error, will try and continue.");
                        }

                        // test for quit and mail request
                        if (incoming instanceof IPTPRetrResponse) {
                            if (incoming.isOk()) {
                                printStatus("Email received from server...");

                                // Create an email object
                                IPTPRetrResponse cr = (IPTPRetrResponse)incoming;
                                Email email = new Email(cr.getMessage().getBytes());

                                // do decryption / verification
                                if (algorithm!=null) {
                                    
                                    boolean retry; 
                                    printStatus("Decrypting/Verifying email...");
                                    
                                    do {
                                        retry = false;
                                                                                
                                        try {
                                            email = algorithm.processIncomingMail(publicKeyHandlers, secretKeyHandlers, email, passPhrases);
                                        } catch (ChecksumFailureException cfe) {
                                            
                                            retry = true;
                                            
                                            PassPhraseResponse reply = requester.requestPassPhrase("Enter passphrase for decryption key", cfe.getMessage());
                                            
                                            if (reply.getResponseCode()==PassPhraseResponse.ABORT) {
                                                // abort
                                                throw new ProxyServerCoreException("Mail transfer aborted by user");
                                            } else {
                                                // add passphrase to list
                                                if (reply.getPassPhrase()!=null) {
                                                    addPassphrase(new PassPhrase(reply.getPassPhrase()));
                                                }     
                                            }
                                        }
                                    } while (retry);
                                }
                                
                                // send email to client
                                protocolServer.sendCommandResponse(new IPTPRetrResponse(true, new String(email.getBytes())));
                            } else {
                                protocolServer.sendCommandResponse(incoming);
                            }

                        }
                        else if(incoming instanceof IPTPQuitResponse) {
                            protocolServer.sendCommandResponse(incoming);
                            protocolServer.disconnectFromClient();
                            protocolClient.disconnectFromServer();
                            break;
                        }
                        else {
                            // send response to email client
                            protocolServer.sendCommandResponse(incoming);
                        }

                        // await command
                        outgoing = protocolServer.awaitCommand();

                        // send command to server
                        protocolClient.sendCommand(outgoing);

                    }
                } catch (ProxyServerCoreException ce) {
                    printErr(ce.getMessage());
                } 

                // At least one socket has dropped, or an error has occurred, perform some cleanup and return to the beginning of the loop
                stopPipe(); // halt the pipe
                setRunning(true); // we don't actually want to stop the pipe at this stage, just close the sockets
                System.gc(); // now should be a good time to do a little bit of cleanup
            }
     	}
}