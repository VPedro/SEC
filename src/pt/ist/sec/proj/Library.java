package pt.ist.sec.proj;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.ConnectException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;

public class Library {

	/*************************************** CLIENT ***************************************/
	private Socket client;
	ObjectOutputStream outObject;
	ObjectInputStream inObject;
	DataOutputStream outData;
	DataInputStream inData;


	public void init(KeyStore keystore, String password){
		//start socket
		String serverName = "";
		int serverPort = 1025;
		try {
			client = new Socket(serverName, serverPort);
			outObject = new ObjectOutputStream(client.getOutputStream());
			inObject = new ObjectInputStream(client.getInputStream());
			outData = new DataOutputStream(client.getOutputStream());
			inData = new DataInputStream(client.getInputStream());
			
			Key key = null;
			try {
				key = keystore.getKey("rgateway", password.toCharArray());
				
			} catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				System.out.println("error loading key");
				
			}
			
			/*
			OutputStream outToServer = client.getOutputStream();
			DataOutputStream out = new DataOutputStream(outToServer);
			out.writeUTF("Hello");
			DataInputStream in = new DataInputStream(client.getInputStream());
			System.out.println(in.readUTF());
			*/
		} catch (UnknownHostException e) {
			e.printStackTrace();
		} catch (ConnectException e1) {
			System.out.println("error initiating library, no server availible");
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	
	public void register_user(){
		/* registers  the  user  on  the  server,  initializing the  
		 * required  data structures to securely store the password
		 */
		Message msg = new Message("register", null, null, null);

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
		try {
			//FIXME enviamos tambem a public key para apagar de um map loggedUsers?
			Message msg = new Message("close", null, null, null);

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
			//close socket
			client.close(); 
		} catch (IOException e) {
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
