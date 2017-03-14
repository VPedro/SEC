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
		Crypto crypto = new Crypto();
		try {
			objIn = new ObjectInputStream(socket.getInputStream());
			objOut = new ObjectOutputStream(socket.getOutputStream());
		} catch (IOException e) {
			System.out.println("IOException");;
		}
		Object input;
		boolean var = true;
		boolean ver_d, ver_u, ver_p;
		while (var) {
			try {
				ver_d = true;
				ver_u = true;
				ver_p = true;
				input = objIn.readObject();
				if (input instanceof Message) {
					Message m = (Message)input;
					if(m.getFunctionName().equals("save_password")){
						ver_d = crypto.signature_verify(m.getSig_domain(), m.getPublicKey(), m.getDomain());
						ver_u = crypto.signature_verify(m.getSig_username(), m.getPublicKey(), m.getUsername());
						ver_p = crypto.signature_verify(m.getSig_password(), m.getPublicKey(), m.getPassword());
						if(ver_d && ver_u && ver_p){
							System.out.println("Signature verified successfully!");
							server.put(m.getPublicKey(), m.getDomain(), m.getUsername(), m.getPassword());
						}
						else {
							System.out.println("Signature not valid!");
						}
					}
					else if(m.getFunctionName().equals("retrieve_password")){
						ver_d = crypto.signature_verify(m.getSig_domain(), m.getPublicKey(), m.getDomain());
						ver_u = crypto.signature_verify(m.getSig_username(), m.getPublicKey(), m.getUsername());
						if(ver_d && ver_u) {
							System.out.println("Signature verified successfully!");
							byte[] pass = server.get(m.getPublicKey(), m.getDomain(), m.getUsername());
							Message m2 = new Message(null, null, null, null, pass, null, null, pass);
							objOut.writeObject(m2);
						}
						else {
							System.out.println("Signature not valid!");
						}
					}
				}
				else if(input instanceof Message2) {
					Message2 m = (Message2)input;

					if(m.getFunc().equals("register")){
						String res = server.register(m); //FIXME
						Message2 m2 = new Message2("register",null,res);
						objOut.writeObject(m2);
					}
					else if(m.getFunc().equals("close")){
						Message2 m2 = new Message2("close", null, "Closing");
						objOut.writeObject(m2);
						var = false;
						server.close();	
						//return;
					}
				}/*else if(input==null){
					server.close();
				}*/
			} catch (ClassNotFoundException e) {
				e.printStackTrace();
			} catch (EOFException e) {
				//e.printStackTrace();
				System.out.println("Exiting"); //FIXME
				var = false;
				//System.exit(0);
			} catch (IOException e) {
				System.out.println("IOException");
				e.printStackTrace();
			}
		}
	}

}