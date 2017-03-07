package pt.ist.sec.proj;

import java.security.Key;
import javax.crypto.*;
public class Server {

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
