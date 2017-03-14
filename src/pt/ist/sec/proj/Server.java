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
		ArrayList<String> list = new ArrayList<String>(); list.add(crypto.encode_base64(domain)); list.add(crypto.encode_base64(username));
		passwords.put(list, crypto.encode_base64(password));
	}
	
	public byte[] get(byte[] domain, byte[] username) throws UnsupportedEncodingException{
		ArrayList<String> list = new ArrayList<String>(); list.add(crypto.encode_base64(domain)); list.add(crypto.encode_base64(username));
		String password_retrieved = passwords.get(list);
		if(password_retrieved != null){
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
		Socket serverClient = null;
		
			try {
				server.serverSocket = new ServerSocket(1025);				
				while(true){
					serverClient = server.serverSocket.accept();
					new ServerThread(serverClient, server).start();
				}
           //server.serverSocket.close();
			
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
}
