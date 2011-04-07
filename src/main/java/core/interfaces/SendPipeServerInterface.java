/* * Oxford Brookes University Secure Email Proxy  * Copyright (C) 2002/3 Oxford Brookes University Secure Email Project * http://secemail.brookes.ac.uk *  * This program is free software; you can redistribute it and/or * modify it under the terms of the GNU General Public License * as published by the Free Software Foundation; either version 2 * of the License, or (at your option) any later version. *  * This program is distributed in the hope that it will be useful, * but WITHOUT ANY WARRANTY; without even the implied warranty of * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the * GNU General Public License for more details. *  * You should have received a copy of the GNU General Public License * along with this program; if not, write to the Free Software * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA. *  * The Secure Email Project is: *  * Marcus Povey <mpovey@brookes.ac.uk> or <icewing@dushka.co.uk> * Damian Branigan <dbranigan@brookes.ac.uk> * George Davson <gdavson@brookes.ac.uk> * David Duce <daduce@brookes.ac.uk> * Simon Hogg <simon.hogg@brookes.ac.uk> * Faye Mitchell <frmitchell@brookes.ac.uk> *  * For further information visit the secure email project website. */package core.interfaces;
import core.exceptions.*;
import core.iptp.*;

/**
 * <p>An interface defining the client side end of the OutgoingEmailPipe which the user's email client connects to.</p>
 *
 * @see core.OutgoingEmailPipe
 */
public abstract interface SendPipeServerInterface
{
    /** Configure what port the server will wait on when awaitConnection is called */
    public abstract void initServerConnection(int port);
     
    /**
     * <p>Await a client connection on a specified port.</p>
     * <p>For security reasons, you MUST ONLY accept connections from Localhost.</p>
     * @throws PipeCommunicationException if there was a general communication problem.
     */
    public abstract void awaitConnection() throws PipeCommunicationException;
   
    /**
     * <p>Disconnect socket and drop any connection.</p>
     * <p>Any socket exceptions caused by closing a socket in accept state are handled internally.</p>
     * @throws PipeCommunicationException if there was a general communication problem.
     */
    public abstract void disconnectFromClient() throws PipeCommunicationException;
    
    /** 
     * <p>Awaits a command from the client.</p>
     * <p>The implementor of this method must take the internet protocol command and parameters and map it 
     * into the appropriate proxy protocol command.</p>
     * <p>This currently only maps selective commands (email transfer etc), otherwise the transaction is just relayed. See the Proxy Protocol
     * paper for details.</p>
     * <p>If you are implementing version 2 or higher of the internal proxy protocol (at time of writing this hasn't been written) you MUST throw a NoMappingPossibleException if no mapping is possible.</p>
     * @throws NoMappingPossibleException if no mapping is possible (future enhancement, see protocol spec).
     * @throws PipeCommunicationException if there was a general communication problem.
     */
    public abstract IPTPCommand awaitCommand() throws NoMappingPossibleException, PipeCommunicationException;
    
    /**
     * <p>Send a command response back to the client.</p>
     * <p>The implementor of this method must take the proxy protocol response code from the server and map it
     * to the appropriate internet protocol code.</p>
     * <p>This currently only maps selective commands (email transfer etc), otherwise the transaction is just relayed. See the Proxy Protocol
     * paper for details.</p>
     * <p>If you are implementing version 2 or higher of the internal proxy protocol (at time of writing this hasn't been written) you MUST throw a NoMappingPossibleException if no mapping is possible.</p>
     * @throws NoMappingPossibleException if no mapping is possible (future enhancement, see protocol spec).
     * @throws PipeCommunicationException if there was a general communication problem.
     */
    public abstract void sendCommandResponse(IPTPCommandResponse commandResponse) throws NoMappingPossibleException, PipeCommunicationException;
    
    /**
     * <p> Returns true if the socket is connected to the email client.</p>
     */
    public abstract boolean isConnectedToClient();
}