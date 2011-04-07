/* * Oxford Brookes University Secure Email Proxy  * Copyright (C) 2002/3 Oxford Brookes University Secure Email Project * http://secemail.brookes.ac.uk *  * This program is free software; you can redistribute it and/or * modify it under the terms of the GNU General Public License * as published by the Free Software Foundation; either version 2 * of the License, or (at your option) any later version. *  * This program is distributed in the hope that it will be useful, * but WITHOUT ANY WARRANTY; without even the implied warranty of * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the * GNU General Public License for more details. *  * You should have received a copy of the GNU General Public License * along with this program; if not, write to the Free Software * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA. *  * The Secure Email Project is: *  * Marcus Povey <mpovey@brookes.ac.uk> or <icewing@dushka.co.uk> * Damian Branigan <dbranigan@brookes.ac.uk> * George Davson <gdavson@brookes.ac.uk> * David Duce <daduce@brookes.ac.uk> * Simon Hogg <simon.hogg@brookes.ac.uk> * Faye Mitchell <frmitchell@brookes.ac.uk> *  * For further information visit the secure email project website. */package core.interfaces;
import core.exceptions.*;
import core.iptp.*;

/**
 * <p>An interface defining the server side end of the OutgoingEmailPipe which connects to the mail server.</p>
 *
 * @see core.OutgoingEmailPipe
 */
public abstract interface SendPipeClientInterface
{
    /** Configure the host that the client connects to with the connect method. */
    public abstract void initClientConnection(String address, int port);
    
    /** 
     * Connects the pipe to the email server.
     * @throws PipeCommunicationException if there was a problem connecting to the remote computer.
     */
    public abstract void connect() throws PipeCommunicationException;
    
    /**
     * Disconnect from the server.
     * @throws PipeCommunicationException if there was a problem connecting to the remote computer.
     */
    public abstract void disconnectFromServer() throws PipeCommunicationException;
    
    /** 
     * <p>Send a command to the email server.</p>
     * <p>The implementor of this method must take the proxy protocol command and parameters and map it 
     * into the appropriate internet protocol command.</p>
     * <p>This currently only maps selective commands (email transfer etc), otherwise the transaction is just relayed. See the Proxy Protocol
     * paper for details.</p>
     * <p>If you are implementing version 2 or higher of the internal proxy protocol (at time of writing this hasn't been written) you MUST throw a NoMappingPossibleException if no mapping is possible.</p>
     * @param command The internal proxy protocol command, together with any parameters.
     * @throws NoMappingPossibleException if no mapping is possible (future enhancement, see protocol spec).
     * @throws PipeCommunicationException if there was a general communication problem.
     */
    public abstract void sendCommand(IPTPCommand command) throws NoMappingPossibleException, PipeCommunicationException;
    
    /**
     * <p>Await a command response from the email server after sending a command.</p>
     * <p>The implementor of this must receive the raw command response text and map it into the appropriate proxy protocol command.</p>
     * <p>This currently only maps selective commands (email transfer etc), otherwise the transaction is just relayed. See the Proxy Protocol
     * paper for details.</p>
     * <p>If you are implementing version 2 or higher of the internal proxy protocol (at time of writing this hasn't been written) you MUST throw a NoMappingPossibleException if no mapping is possible.</p>
     * @throws NoMappingPossibleException if no mapping is possible (future enhancement, see protocol spec).
     * @throws PipeCommunicationException if there was a general communication problem.
     */
    public abstract IPTPCommandResponse awaitCommandResponse() throws NoMappingPossibleException, PipeCommunicationException;
 
    /**
     * <p> Returns true if the socket is connected to the email server.</p>
     */
    public abstract boolean isConnectedToServer();
}