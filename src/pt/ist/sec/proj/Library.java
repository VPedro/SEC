package pt.ist.sec.proj;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.ConnectException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.*;


public class Library {

	/*************************************** CLIENT ***************************************/
	private Socket client;
	ObjectOutputStream outObject;
	ObjectInputStream inObject;
	DataOutputStream outData;
	DataInputStream inData;

	static PublicKey pubKey;
	static PrivateKey privKey;
	
	Crypto crypto;

	public boolean init(KeyStore keystore, String password){
		//start socket
		String serverName = "";
		int serverPort = 1025;
		crypto = new Crypto();
		try {
			client = new Socket(serverName, serverPort);
			outObject = new ObjectOutputStream(client.getOutputStream());
			inObject = new ObjectInputStream(client.getInputStream());
			outData = new DataOutputStream(client.getOutputStream());
			inData = new DataInputStream(client.getInputStream());
			setKeys(keystore, password);
			return true;

		} catch (UnknownHostException e) {
			e.printStackTrace();
			return false;
		} catch (ConnectException e1) {
			System.out.println("error initiating library, no server availible");
			return false;
		} catch (IOException e) {
			e.printStackTrace();
			return false;
		}
	}

	
	private void setKeys(KeyStore ks, String password) {
		try {
			//Get the key with the given alias.
			String alias="rgateway";
			
			pubKey = ks.getCertificate(alias).getPublicKey();
			privKey = (PrivateKey) ks.getKey(alias, password.toCharArray());
			
		} catch (Exception e){
			
		}
		
	}


	public void register_user(){
		/* registers  the  user  on  the  server,  initializing the  
		 * required  data structures to securely store the password
		 */
		Message2 msg = new Message2("register", pubKey, null);

		Message2 resMsg = null;
		try {
			outObject.writeObject(msg);
			resMsg = (Message2)inObject.readObject();
			System.out.println("result from server: " + resMsg.getRes());
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}
		
	}

	public void save_password(byte[] domain, byte[] username, byte[] password) throws IOException {
		/* stores  the  triple  (domain, username, password)  on  the  server. 
		 * This corresponds	to an insertion	if the (domain,	username) pair is 
		 * not already known by the server, or to an update otherwise. 
		*/
		
		Message msg = new Message("save_password", domain, username, crypto.encrypt(password, pubKey));
		outObject.writeObject(msg);
	}
	
	public String retrieve_password(byte[] domain, byte[] username){
		/* retrieves the password associated with the given (domain,username) 
		 * pair. The behavior of what should happen if the (domain, username) 
		 * pair does not exist is unspecified. 
		 */
		
		Message msg = new Message("retrieve_password", domain, username, null);

		Message m = null;
		try {
			outObject.writeObject(msg);
			m = (Message)inObject.readObject();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		//TODO verify signature and decript if valid
		byte[] b = crypto.decrypt(m.getPassword(), privKey);
		if (b == null){ return null;}
		try {
			return new String(b, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public void close(){
		/* concludes the current session of commands with the client library */
		
		//removeKeys
		
		//FIXME enviamos tambem a public key para apagar de um map loggedUsers?
		Message2 msg = new Message2("close", pubKey, null);

		Message2 resMsg = null;
		try {
			outObject.writeObject(msg);
			resMsg = (Message2)inObject.readObject();
			System.out.println("result from server: " + resMsg.getRes());
			//FIXME close socket
			//client.close();
			//System.exit(0);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
