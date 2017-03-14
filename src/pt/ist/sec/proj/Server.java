package pt.ist.sec.proj;

import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
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
	private Map<ArrayList<String>, PublicKey> publicKeys;	
	private Map<PublicKey, Integer> nounces;
	private List<Integer> usedNounces;
	private Crypto crypto;
	
	public PublicKey getKey(byte[] domain, byte[] username){
		ArrayList<String> list = new ArrayList<String>(); list.add(crypto.encode_base64(domain)); list.add(crypto.encode_base64(username));
		PublicKey key_retrieved = publicKeys.get(list);
		return key_retrieved;
	}
	
	public void putKey(byte[] domain, byte[] username, PublicKey publicKey){
		ArrayList<String> list = new ArrayList<String>(); list.add(crypto.encode_base64(domain)); list.add(crypto.encode_base64(username));
		publicKeys.put(list, publicKey);
	}
	
	public void putMap(byte[] domain, byte[] username, byte[] password){
		ArrayList<String> list = new ArrayList<String>(); list.add(crypto.encode_base64(domain)); list.add(crypto.encode_base64(username));
		passwords.put(list, crypto.encode_base64(password));
	}
	
	public byte[] getMapValue(byte[] domain, byte[] username) throws UnsupportedEncodingException{
		ArrayList<String> list = new ArrayList<String>(); list.add(crypto.encode_base64(domain)); list.add(crypto.encode_base64(username));
		String password_retrieved = passwords.get(list);
		if(password_retrieved != null){
			return crypto.decode_base64(password_retrieved);
		}
		else {
			return null;
		}
	}
	
		/** Requirements:
		 *	Non-Repudiation of any action that alters passwords
		 *  Confidentiality and Integrity of domains, usernames and passwords 
		 **/
			
			public void register(Key publicKey){ 
				/* registers the user in the server. Anomalous or unauthorized
				 * requests should return an appropriate exception or error code
				 */
			}
			
			public void	put(Key publicKey, byte[] domain, byte[] username, byte[] password){ 
				System.out.println("Save_password received.");
				putMap(domain, username, password);
			}
			
			public byte[] get(Key publicKey, byte[] domain, byte[] username){
				System.out.println("Retrieve_password received.");
				byte[] pass = null;
				try {
					pass = getMapValue(domain, username);
				} catch (UnsupportedEncodingException e) {
					e.printStackTrace();
				}
				return pass;
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
