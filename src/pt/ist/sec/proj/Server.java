package pt.ist.sec.proj;

import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


public class Server {

	private ServerSocket serverSocket;
	private Map<ArrayList<String>, String> passwords;
	private Map<PublicKey, Integer> nounces;
	private List<Integer> usedNounces;
	private Crypto crypto;
	
	public void put(byte[] domain, byte[] username, byte[] password){
		System.out.println("put password received");
		ArrayList<String> list = new ArrayList<String>(); list.add(crypto.encode_base64(domain)); list.add(crypto.encode_base64(username));
		passwords.put(list, crypto.encode_base64(password));
		System.out.println("saved: "+ crypto.encode_base64(password));
	}
	
	public byte[] get(byte[] domain, byte[] username) throws UnsupportedEncodingException{
		ArrayList<String> list = new ArrayList<String>(); list.add(crypto.encode_base64(domain)); list.add(crypto.encode_base64(username));
		String password_retrieved = passwords.get(list);
		if(password_retrieved != null){
			System.out.println("decoded pss: "+crypto.decode_base64(password_retrieved));// + crypto.decode_base64(password_retrieved));
			return crypto.decode_base64(password_retrieved);
		}
		else {
			return null;
		}
	}
	
	public String register(Message2 msg){
		System.out.println("register command received");
		
		//decripts with msg.getPubKey()
		
		//verifies hash 
		
		//return Anomalous or unauthorized
		
		//if ja esta noutro disp return nounce atual
		
		int nounce = getNounce();
		nounces.put(msg.getPubKey(), nounce);
		
		return "Success";
	}
	
	public String close(){
		System.out.println("close command received");
		return "Success";
	}
	
	public int getNounce(){
		int res = 0;
		try {
			SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
			res = random.nextInt();
			while(usedNounces.contains(res)){
				res = random.nextInt();
			}
			usedNounces.add(res);
			System.out.println("generated nounce: " + res);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return res;
	}
	
	
	public static void main(String args[]){
		
		Server server = new Server();
		server.crypto = new Crypto();
		server.passwords = new HashMap<ArrayList<String>, String>();
		server.nounces = new HashMap<PublicKey, Integer>();
		server.usedNounces = new ArrayList<Integer>();
		
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
    						String result = server.register(m);
    						Message2 m2 = new Message2("register",null,result);
    						objOut.writeObject(m2);
    					}
    					else if(m.getFunc().equals("close")){
    						String result = server.close();
    						Message2 m2 = new Message2("close", null, result);
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
