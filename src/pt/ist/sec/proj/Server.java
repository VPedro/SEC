package pt.ist.sec.proj;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


public class Server {

	private ServerSocket serverSocket;
	//private Map<ArrayList<String>, String> passwords;
	private Map<String, byte[]> newPass;
	private Map<PublicKey, Long> nonces;
	private List<PublicKey> registeredKeys;
	private List<Long> usedNonces;
	boolean verbose = false;

	public Map<PublicKey, Long> getNonces(){
		return nonces;
	}
	
	public List<Long> getUsedNonces(){
		return usedNonces;
	}
	
	PublicKey pubKey;
	PrivateKey privKey;

	private void setKeys(KeyStore ks, String alias, String password) {
		try {
			//Get the keys for the given alias.			
			pubKey = ks.getCertificate(alias).getPublicKey();
			privKey = (PrivateKey) ks.getKey(alias, password.toCharArray());
			System.out.println("Loaded keys from keystore with success");
		} catch (Exception e){
			e.printStackTrace();
			System.out.println("Impossible to load keys from keystore to library!");
		}

	}

	public KeyStore getKeyStore(String pass){ //created with "olaola" as password
		KeyStore ks = null;
		try { //If KeyStore file already exists
			//FIXME remove hardcoded alias and password
			FileInputStream fis = new FileInputStream("serverkeystorefile.jce");	//Open the KeyStore file
			ks = KeyStore.getInstance("JCEKS"); //Create an instance of KeyStore of type “JCEKS”
			ks.load(fis, pass.toCharArray()); //Load the key entries from the file into the KeyStore object.
			fis.close();
			System.out.println("KeyStore Loaded");
		} //create it if cannot find it
		catch (FileNotFoundException e) {	
			System.out.println("Please create a keystore using keytool first");
		} catch (NoSuchAlgorithmException | CertificateException | KeyStoreException e) {
			e.printStackTrace();
			ks = null;
		} catch (IOException e){
			ks = null;
		}
		return ks;
	}

	/** Requirements:
	 *	Non-Repudiation of any action that alters passwords
	 *  Confidentiality and Integrity of domains, usernames and passwords 
	 * @return 
	 **/

	public SignedMessage register(SignedMessage msg){ 
		//Verify if publicKey is already registered
		if(registeredKeys.contains(msg.getPubKey())){
			msg.setRes("used key");
			System.out.println("Already registered, aborted!");
			return msg;
		}
		else{
			registeredKeys.add(msg.getPubKey());
			msg.setRes("success");
			return msg;
		}
	}

	public void	put(PublicKey publicKey, byte[] domain, byte[] username, byte[] password){ 
		System.out.println("Server executed: Save_password");
		byte[] c = new byte[pubKey.getEncoded().length + domain.length + username.length];
		System.arraycopy(pubKey.getEncoded(), 0, c, 0, pubKey.getEncoded().length);
		System.arraycopy(domain, 0, c, pubKey.getEncoded().length, domain.length);
		System.arraycopy(username, 0, c, pubKey.getEncoded().length + domain.length, username.length);
		newPass.put(new String(c), password);
	}

	public byte[] get(PublicKey publicKey, byte[] domain, byte[] username){
		System.out.println("Server executed: Retrieve_password");
		byte[] c = new byte[pubKey.getEncoded().length + domain.length + username.length];
		System.arraycopy(pubKey.getEncoded(), 0, c, 0, pubKey.getEncoded().length);
		System.arraycopy(domain, 0, c, pubKey.getEncoded().length, domain.length);
		System.arraycopy(username, 0, c, pubKey.getEncoded().length + domain.length, username.length);
		
		byte[] password_retrieved = newPass.get(new String(c));
		if(password_retrieved != null){
			return password_retrieved;
		}else {
			return null;
		}
	}

	public long getNonce(){
		long res = 0;
		try {
			SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
			res = random.nextLong();
			while(usedNonces.contains(res)){
				res = random.nextLong();
			}
			usedNonces.add(res);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return 0;
		}
		return res;
	}


	public static void main(String args[]){

		Server server = new Server();
		server.newPass = new HashMap<String, byte[]>();
		server.nonces = new HashMap<PublicKey, Long>();
		server.usedNonces = new ArrayList<Long>();
		server.registeredKeys = new ArrayList<PublicKey>();

		KeyStore ks  = server.getKeyStore("olaola");
		server.setKeys(ks,"server","olaola");

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

	PublicKey getPubKey() {
		return pubKey;
	}

	PrivateKey getPrivKey() {
		return privKey;
	}

	public List<PublicKey> getRegisteredKeys() {
		return registeredKeys;
	}

	public void setRegisteredKeys(List<PublicKey> registeredKeys) {
		this.registeredKeys = registeredKeys;
	}

}
