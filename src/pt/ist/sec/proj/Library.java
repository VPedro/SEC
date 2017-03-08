package pt.ist.sec.proj;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.Key;
import java.security.KeyStore;

public class Library {

	/*************************************** CLIENT ***************************************/
	private Socket client;
	

	public void init(KeyStore keystore){

		//start socket
		String serverName = "";
		int serverPort = 85;
		try {
			client = new Socket(serverName, serverPort);
			/*
			OutputStream outToServer = client.getOutputStream();
			DataOutputStream out = new DataOutputStream(outToServer);
			out.writeUTF("Hello");
			DataInputStream in = new DataInputStream(client.getInputStream());
			System.out.println(in.readUTF());
			*/
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	public void test(byte[] array){
		String cona = new String(array);
		System.out.println(cona);
	}
	
	public void register_user(){
		/* registers  the  user  on  the  server,  initializing the  
		 * required  data structures to securely store the password
		 */
	}

	public void save_password(byte[] domain, byte[] username, byte[] password) throws IOException {
		/* stores  the  triple  (domain, username, password)  on  the  server. 
		 * This corresponds	to an insertion	if the (domain,	username) pair is 
		 * not already known by the server, or to an update otherwise. 
		*/
		
		Message msg = new Message("save_password", domain, username, password);
		ObjectOutputStream output = new ObjectOutputStream(client.getOutputStream());
		output.writeObject(msg);
		DataInputStream in = new DataInputStream(client.getInputStream());
		System.out.println("result from server "+in.readBoolean());
	}
	
	public byte[] retrieve_password(byte[] domain, byte[] username){
		/* retrieves the password associated with the given (domain,username) 
		 * pair. The behavior of what should happen if the (domain, username) 
		 * pair does not exist is unspecified. 
		 */
		
		Message msg = new Message("retrieve_password", domain, username, null);
		ObjectOutputStream output;
		ObjectInputStream input = null;
		Message m = null;
		try {
			output = new ObjectOutputStream(client.getOutputStream());
			output.writeObject(msg);
			DataInputStream in = new DataInputStream(client.getInputStream());
			System.out.println(in.readUTF());
			input = new ObjectInputStream(client.getInputStream());	
			m = (Message)input.readObject();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return m.getPassword();
	}
	
	public void close(){
		/* concludes the current session of commands with the client library */
		try {
			client.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
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
