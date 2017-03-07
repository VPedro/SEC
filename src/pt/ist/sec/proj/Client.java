package pt.ist.sec.proj;

import java.security.*;

public class Client {

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
	
}
