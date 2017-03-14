package pt.ist.sec.proj;

import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;


public class Server {

	private ServerSocket serverSocket;
	private Map<ArrayList<String>, String> map;
	private Crypto crypto;
	
	public void put(byte[] domain, byte[] username, byte[] password){ 
		ArrayList<String> list = new ArrayList<String>(); list.add(crypto.encode_base64(domain)); list.add(crypto.encode_base64(username));
		map.put(list, crypto.encode_base64(password));
	}
	
	public byte[] get(byte[] domain, byte[] username) throws UnsupportedEncodingException{
		ArrayList<String> list = new ArrayList<String>(); list.add(crypto.encode_base64(domain)); list.add(crypto.encode_base64(username));
		String password_retrieved = map.get(list);
		if(password_retrieved != null){
			return crypto.decode_base64(password_retrieved);
		}
		else {
			return null;
		}
	}
	
	
	
	public static void main(String args[]){
		
		Server server = new Server();
		server.crypto = new Crypto();
		server.map = new HashMap<ArrayList<String>, String>();
		
		System.out.println("===== Server Started =====");
		try {
			server.serverSocket = new ServerSocket(1025);
			Socket serverClient = server.serverSocket.accept();
	
			//DataInputStream in = new DataInputStream(server.getInputStream());
			DataOutputStream out = new DataOutputStream(serverClient.getOutputStream());
			//System.out.println(in.readUTF());
            //out.writeUTF("Goodbye!");
			ObjectInputStream objIn = new ObjectInputStream(serverClient.getInputStream());
			ObjectOutputStream objOut = new ObjectOutputStream(serverClient.getOutputStream());
            while(true){ //serverClient.getInputStream().read() != -1  => FILTHY HACK, GARBAGE, explodes on save password
            	try {
					Message m = (Message)objIn.readObject();
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
				} catch (ClassNotFoundException e) {
					e.printStackTrace();
				} catch (EOFException e) {
					System.out.println("Connection closed"); //FIXME 
				}
           }            
           //server.serverSocket.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
}
