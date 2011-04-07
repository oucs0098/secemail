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
import java.net.*;
import java.io.*;

/**
 * <p>Common low level protocol functions.</p>
 * <p>This class provides low level methods and fields common to all protocol handlers.</p>
 * <p>It provides a common set of functions that make up the protocol transport layer.</p>
 * <p>Primarily this implements the low level methods of the Recv* and Send* interfaces.</p>
 * @see core.interfaces.RecvPipeClientInterface
 * @see core.interfaces.RecvPipeServerInterface
 * @see core.interfaces.SendPipeClientInterface
 * @see core.interfaces.SendPipeServerInterface
 */
public abstract class ProtocolHandler {

    /** Keep a record of the last command sent to the server. */
    protected IPTPCommand lastCommandToServer;

    /** Port to connect to on remote machine */
    protected int connectPort;
    /** The hostname of the remote machine */
    protected String connectHostname;
    /** Socket to connect to remote machine with */
    protected Socket clientSocket;
    /** Stream to read from server */
    protected BufferedReader clientInputStream;
    /** Stream to write to server */
    protected BufferedWriter clientOutputStream;

    /** Port to listen for connection on */
    protected int listenPort;
    /** Socket to listen on */
    protected ServerSocket serverSocket;
    /** Socket returned by serverSocket.accept() */
    protected Socket emailClientConnection;
    /** Stream to read from client */
    protected BufferedReader serverInputStream;
    /** Stream to write to client */
    protected BufferedWriter serverOutputStream;

    /** True if the we are connected to the server */
    private boolean clientConnected = false;
    /** True if we have a connection from the mail client */
    private boolean emailClientConnected = false;

    /** Configure the host that the client connects to with the connect method.  */
    public void initClientConnection(String address, int port) {
        connectPort = port;
        connectHostname = address;
        clientConnected = false;
    }

    /** Configure what port the server will wait on when awaitConnection is called  */
    public void initServerConnection(int port) {
        listenPort = port;
        emailClientConnected = false;
    }

    /**
     * Connects the pipe to the email server.
     * @throws PipeCommunicationException if there was a problem connecting to the remote computer.
     */
    public void connect() throws PipeCommunicationException {
        try {
            clientSocket = null;
            clientSocket = new Socket(connectHostname, connectPort);
            clientInputStream = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            clientOutputStream = new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream()));
        } catch (IOException e) {
            clientConnected = false;
            throw new PipeCommunicationException("Could not connect to host, " + e.getMessage());
        }
        
        clientConnected = true; // if we got here then we are connected
    }

    /**
     * <p>Await a client connection on a specified port.</p>
     * <p>For security reasons, you MUST ONLY accept connections from Localhost.</p>
     * @throws PipeCommunicationException if there was a general communication problem.
     */
    public void awaitConnection() throws PipeCommunicationException {
        try {
            serverSocket = null;
            emailClientConnection = null;

            serverSocket = new ServerSocket(listenPort);
            emailClientConnection = serverSocket.accept();

            serverInputStream = new BufferedReader(new InputStreamReader(emailClientConnection.getInputStream()));
            serverOutputStream = new BufferedWriter(new OutputStreamWriter(emailClientConnection.getOutputStream()));

            InetAddress i = emailClientConnection.getInetAddress();
            byte[] b = i.getAddress();
            if (b[0]!=127) {
                emailClientConnection.close();
                emailClientConnected = false;
                throw new PipeCommunicationException("Connection attempt from remote computer! (" + emailClientConnection.getInetAddress().getHostName() + ")");
            }

        } catch (IOException e) {
            emailClientConnected = false;
            throw new PipeCommunicationException(e.getMessage());
        }
        
        emailClientConnected = true; // if we got here then we are connected
    }

    /**
     * <p>Disconnect socket and drop any connection.</p>
     * <p>Any socket exceptions caused by closing a socket in accept state are handled internally.</p>
     * @throws PipeCommunicationException if there was a general communication problem.
     */
    public void disconnectFromClient() throws PipeCommunicationException {
        try {
                serverInputStream.close();
                serverOutputStream.close();
                emailClientConnected = false;

                if (emailClientConnection!=null) emailClientConnection.close();
                if (serverSocket!=null) serverSocket.close();

        } catch (IOException e) {
            throw new PipeCommunicationException(e.getMessage());
        }
    }

    /**
     * Disconnect from the server.
     * @throws PipeCommunicationException if there was a problem connecting to the remote computer.
     */
    public void disconnectFromServer() throws PipeCommunicationException {
        try {
            lastCommandToServer = null; // reset server command
            clientConnected = false;
            
            if (clientSocket!=null) {
                clientInputStream.close();
                clientOutputStream.close();
                clientSocket.close();
            }

        } catch (IOException e) {
            throw new PipeCommunicationException(e.getMessage());
        }
    }
    
    /**
     * <p> Returns true if the socket is connected to the email server.</p>
     */
    public boolean isConnectedToServer() {
        // return clientSocket.isConnected();
        return clientConnected;
    }

    /**
     * <p> Returns true if the socket is connected to the email client.</p>
     */
    public boolean isConnectedToClient() {
        //return emailClientConnection.isConnected();
        return emailClientConnected;
    }

    /**
     * <p> Reads a single command line from the client, performing no protocol conversion.</p>
     * <p> Multiline responses must be explicitly tested for and read line by line. </p>
     * @throws PipeCommunicationException if there was a problem.
     */
    protected String awaitRawCommandLine() throws PipeCommunicationException {
        // read from client
        String data;

        if (emailClientConnection==null)
            throw new PipeCommunicationException("Client socket not connected.");

        try {

            data = serverInputStream.readLine();

        } catch (IOException e) {
            throw new PipeCommunicationException(e.getMessage());
        }

        return data;
        
    }

    /**
     * <p> Await a command line reply from the server and return the received data performing no protocol conversion.</p>
     * <p> Multiline responses must be explicitly tested for and read line by line. </p>
     * @throws PipeCommunicationException if there was a problem.
     */
    protected String awaitRawCommandResponseLine() throws PipeCommunicationException {
        // read from server
        String data;

        if (clientSocket==null)
            throw new PipeCommunicationException("Socket not connected to server.");

        try {

            data = clientInputStream.readLine();

        } catch (IOException e) {
            throw new PipeCommunicationException(e.getMessage());
        }

        return data;
    }

    /**
     * <p>Send a raw command string to the server with absolutely no protocol conversion.</p>
     * @throws PipeCommunicationException if there was a problem.
     */
    protected void sendRawCommand(String command) throws PipeCommunicationException {
        // talk to server

        if (clientSocket==null)
            throw new PipeCommunicationException("Socket not connected to server.");

        try {
            clientOutputStream.write(command);

            clientOutputStream.flush();

        } catch (IOException e) {
            throw new PipeCommunicationException(e.getMessage());
        }
    }

    /**
     * <p>Send a raw command response string to the client with absolutely no protocol conversion.</p>
     * @throws PipeCommunicationException if there was a problem.
     */
    protected void sendRawCommandResponse(String commandResponse) throws PipeCommunicationException {
        // talk to client

        if (emailClientConnection==null)
            throw new PipeCommunicationException("Client socket not connected.");

        try {
            serverOutputStream.write(commandResponse);

            serverOutputStream.flush();

        } catch (IOException e) {
            throw new PipeCommunicationException(e.getMessage());
        }
    }
}
