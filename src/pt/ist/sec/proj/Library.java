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
	
	private long nextNounce;
	
	Crypto crypto;

	public boolean init(KeyStore keystore, String alias, String password){
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
			setKeys(keystore, alias, password);
			
			nextNounce = getNouce();
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

	
	private long getNouce() {
		long res = 0;
		
		byte[] sig_pub = crypto.signature_generate(pubKey.getEncoded(), privKey);
		
		SignedMessage msg = new SignedMessage("nounce", pubKey, sig_pub,  null);
		SignedMessage resMsg = null;
		try {
			outObject.writeObject(msg);
			resMsg = (SignedMessage)inObject.readObject();
			Long l = Long.valueOf(resMsg.getRes()).longValue();
			System.out.println("nounce reveived: " + l);
			
			nextNounce = l;
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
			return 0;
		}
		
		return res;
	}


	private void setKeys(KeyStore ks, String alias, String password) {
		try {
			//Get the keys for the given alias.			
			pubKey = ks.getCertificate(alias).getPublicKey();
			privKey = (PrivateKey) ks.getKey(alias, password.toCharArray());
			
		} catch (Exception e){
			e.printStackTrace();
			System.out.println("impossible to load keys from keystore to library");
		}
		
	}


	public boolean register_user(){
		/* registers  the  user  on  the  server,  initializing the  
		 * required  data structures to securely store the password
		 */
		//SignedMessage msg = createRegMessage("");
		byte[] sig_pub = crypto.signature_generate(pubKey.getEncoded(), privKey);
		
		SignedMessage msg = new SignedMessage("register", pubKey, sig_pub,  null);
		SignedMessage resMsg = null;
		try {
			outObject.writeObject(msg);
			resMsg = (SignedMessage)inObject.readObject();
			System.out.println("result from server: " + resMsg.getRes());
			return true;
		} catch (IOException e) {
			//e.printStackTrace();
			return false;
		} catch (ClassNotFoundException e) {
			//e.printStackTrace();
			return false;
		}
		
	}
	
	public Message createMessage(String s, byte[] domain, byte[] username, byte[] password) {
		byte[] sig_d = crypto.signature_generate(domain, privKey);
		byte[] sig_u = crypto.signature_generate(username, privKey);
		byte[] p = crypto.encrypt(password, pubKey);
		byte[] sig_p = crypto.signature_generate(p, privKey);
		
		return new Message(s, pubKey, sig_d, sig_u, sig_p, domain, username, p);
	}

	public void save_password(byte[] domain, byte[] username, byte[] password) throws IOException {
		Message msg = createMessage("save_password", domain, username, password);
		outObject.writeObject(msg);
	}
	
	//SIGN_VERIFY recebe as chaves de quem? ou dos dois?
	
	public String retrieve_password(byte[] domain, byte[] username){
		Message msg = createMessage("retrieve_password", domain, username, null);

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
