package pt.ist.sec.proj;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.Socket;

public class ServerThread extends Thread {
	
	private Socket socket;
	private Server server;

    public ServerThread(Socket clientSocket, Server server) {
        this.socket = clientSocket;
        this.server = server;
    }

    public void run() {
        ObjectInputStream objIn = null;
        ObjectOutputStream objOut = null;
        try {
            objIn = new ObjectInputStream(socket.getInputStream());
            objOut = new ObjectOutputStream(socket.getOutputStream());
        } catch (IOException e) {
            System.out.println("IOException");;
        }
        Object input;
        while (true) {
        	try {
        		input = objIn.readObject();
        		if (input instanceof Message) {
        			Message m = (Message)input;
        			if(m.getFunctionName().equals("save_password")){
						System.out.println("Save_password received.");
						server.put(m.getDomain(), m.getUsername(), m.getPassword());
						//out.writeUTF("Password saved!");
					}
					else if(m.getFunctionName().equals("retrieve_password")){
						System.out.println("Retrieve_password received.");
						byte[] pass = server.get(m.getDomain(), m.getUsername());
						Message m2 = new Message(null, null, null, pass);
						objOut.writeObject(m2);
					}
        		}else if(input instanceof Message2) {
        			Message2 m = (Message2)input;
					
					if(m.getFunc().equals("register")){
						String res = server.register(m); //FIXME
						Message2 m2 = new Message2("register",null,res);
						objOut.writeObject(m2);
					}
					else if(m.getFunc().equals("close")){
						String res = server.close();
						Message2 m2 = new Message2("close", null, res);
						objOut.writeObject(m2);
						
					}
				}
			} catch (ClassNotFoundException e) {
				e.printStackTrace();
			} catch (EOFException e) {
				//e.printStackTrace();
				System.out.println("EOFException"); //FIXME
				//System.exit(0);
			} catch (IOException e) {
				System.out.println("IOException");
				e.printStackTrace();
			}
        }
    }

}
