package pt.ist.sec.proj;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.Key;
import java.security.KeyStore;

public class Library {

	/*************************************** CLIENT ***************************************/
	
	public void init(KeyStore keystore){
		/* initializes  the  library  before its  first	use. This  
		 * method should receive a reference to a  key store that 
		 * must	contain the private and public key of  the  user,
		 * as  well  as  any  other  parameters  needed  to  access
		 * this  key  store	(e.g., its password) and to correctly 
		 * initialize the cryptographic primitives used at the 
		 * client side. These keys maintained by the key store
		 * will	be the ones	used in	the	following session of 
		 * commands issued at the client side, until a close()
		 * function is called
		 */

		//start socket
		String serverName = "";
		int serverPort = 85;
		try {
			Socket client = new Socket(serverName, serverPort);
			
			OutputStream outToServer = client.getOutputStream();
			DataOutputStream out = new DataOutputStream(outToServer);
			out.writeUTF("Hello");
			DataInputStream in = new DataInputStream(client.getInputStream());
			System.out.println(in.readUTF());
			
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	public void register_user(){
		/* registers  the  user  on  the  server,  initializing the  
		 * required  data structures to securely store the password
		 */
	}
	
	public void save_password(byte[] domain, byte[] username, byte[] password){
		/* stores  the  triple  (domain, username, password)  on  the  server. 
		 * This corresponds	to an insertion	if the (domain,	username) pair is 
		 * not already known by the server, or to an update otherwise. 
		 */
	}
	
	public byte[] retrieve_password(byte[] domain, byte[] username){
		/* retrieves the password associated with the given (domain,username) 
		 * pair. The behavior of what should happen if the (domain, username) 
		 * pair does not exist is unspecified. 
		 */
		return null;
	}
	
	public void close(){
		/* concludes the current session of commands with the client library */
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
