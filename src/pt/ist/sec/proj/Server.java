package pt.ist.sec.proj;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import java.util.Base64;
import javax.crypto.*;

public class Server {

	private ServerSocket serverSocket;
	private Map<ArrayList<String>, String> map;
	private Crypto crypto;
	
	public void put(byte[] domain, byte[] username, byte[] password){
		System.out.println("put password received");
		ArrayList<String> list = new ArrayList<String>(); list.add(crypto.encode_base64(domain)); list.add(crypto.encode_base64(username));
		map.put(list, crypto.encode_base64(password));
		System.out.println("saved: "+ crypto.encode_base64(password));
	}
	
	public byte[] get(byte[] domain, byte[] username) throws UnsupportedEncodingException{
		ArrayList<String> list = new ArrayList<String>(); list.add(crypto.encode_base64(domain)); list.add(crypto.encode_base64(username));
		String password_retrieved = map.get(list);
		if(password_retrieved != null){
			System.out.println("decoded pss: "+crypto.decode_base64(password_retrieved));// + crypto.decode_base64(password_retrieved));
			return crypto.decode_base64(password_retrieved);
		}
		else {
			return null;
		}
	}
	
	//FIXME Key publicKey AS INPUT
	public String register(){
		System.out.println("register command received");
		return "Success";
	}
	
	public String close(){
		System.out.println("close command received");
		return "Success";
	}
	
	
	public static void main(String args[]){
		
		Server server = new Server();
		server.crypto = new Crypto();
		server.map = new HashMap<ArrayList<String>, String>();
		
		//FIXME save open connection and close them on close message
		
		System.out.println("===== Server Started =====");
		try {
			server.serverSocket = new ServerSocket(1025);
			Socket serverClient = server.serverSocket.accept();
	
			//DataInputStream in = new DataInputStream(server.getInputStream());
			//DataOutputStream out = new DataOutputStream(serverClient.getOutputStream());
			//System.out.println(in.readUTF());
            //out.writeUTF("Goodbye!");
			ObjectInputStream objIn = new ObjectInputStream(serverClient.getInputStream());
			ObjectOutputStream objOut = new ObjectOutputStream(serverClient.getOutputStream());
            
			Object input;
			while(true){ //serverClient.getInputStream().read() != -1  => FILTHY HACK, GARBAGE, explodes on save password
            	System.out.println("");
            	try {
            		input = objIn.readObject();
            		//System.out.println("received: " + input);
            		
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
    						String res = server.register();
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
					System.out.println("EOF"); //FIXME
					//System.exit(0);
				}
           }            
           //server.serverSocket.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
}
