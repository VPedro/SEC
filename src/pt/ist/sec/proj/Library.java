package pt.ist.sec.proj;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
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

	PublicKey pubKey;
	PrivateKey privKey;

	public boolean init(KeyStore keystore, String password){
		//start socket
		String serverName = "";
		int serverPort = 1025;
		try {
			System.out.println("1");
			client = new Socket(serverName, serverPort);
			System.out.println("2");
			outObject = new ObjectOutputStream(client.getOutputStream());
			System.out.println("3");
			inObject = new ObjectInputStream(client.getInputStream());
			System.out.println("4");
			outData = new DataOutputStream(client.getOutputStream());
			System.out.println("5");
			inData = new DataInputStream(client.getInputStream());
			System.out.println("6");
			setKeys(keystore, password);
			System.out.println("7");
			return true;
			/*
			OutputStream outToServer = client.getOutputStream();
			DataOutputStream out = new DataOutputStream(outToServer);
			out.writeUTF("Hello");
			DataInputStream in = new DataInputStream(client.getInputStream());
			System.out.println(in.readUTF());
			*/
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
		//Open the KeyStore file
		FileInputStream fis;
		try {
			//Get the key with the given alias.
			String alias="rgateway";
			
			PublicKey pubKey = ks.getCertificate(alias).getPublicKey();
			PrivateKey privKey = (PrivateKey) ks.getKey(alias, password.toCharArray());
			
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
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

	public void save_password(byte[] domain, byte[] username, byte[] password) throws IOException {
		/* stores  the  triple  (domain, username, password)  on  the  server. 
		 * This corresponds	to an insertion	if the (domain,	username) pair is 
		 * not already known by the server, or to an update otherwise. 
		*/
		
		Message msg = new Message("save_password", domain, username, password);
		outObject.writeObject(msg);
	}
	
	public byte[] retrieve_password(byte[] domain, byte[] username){
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
		return m.getPassword();
	}
	
	public void close(){
		/* concludes the current session of commands with the client library */
		
		//FIXME enviamos tambem a public key para apagar de um map loggedUsers?
		Message2 msg = new Message2("close", pubKey, null);

		Message2 resMsg = null;
		try {
			outObject.writeObject(msg);
			resMsg = (Message2)inObject.readObject();
			System.out.println("result from server: " + resMsg.getRes());
			//FIXME close socket
			//client.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
		
		
	
	//FIXME isto nao devia ser apagado?? estes metodos sao para ser implementados no server
	/*************************************** SERVER ***************************************/
	
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
			/* stores the triple (domain, username, password) on the server. 
			 * This corresponds to an insertion if the (domain, username) pair is 
			 * not already known by the server, or to an update otherwise.
			 * Anomalous or unauthorized requests should return an appropriate 
			 * exception or error code
			 */
		}
		
		public byte[] get(Key publicKey, byte[] domain, byte[] username){
			/* retrieves the password associated with the given (domain, username) 
			 * pair. Anomalous or unauthorized requests should return an appropriate 
			 * exception or	error code
			 */
			return null;
		}

}
