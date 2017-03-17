package pt.ist.sec.proj;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
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
	private Map<PublicKey, Long> nounces;
	private List<PublicKey> registeredKeys;
	private List<Long> usedNounces;

	public Map<PublicKey, Long> getNounces(){
		return nounces;
	}
	
	public List<Long> getUsedNounces(){
		return usedNounces;
	}
	
	PublicKey pubKey;
	PrivateKey privKey;

	public void putMap(PublicKey pubKey, byte[] domain, byte[] username, byte[] password){
		byte[] c = new byte[pubKey.getEncoded().length + domain.length + username.length];
		System.arraycopy(pubKey.getEncoded(), 0, c, 0, pubKey.getEncoded().length);
		System.arraycopy(domain, 0, c, pubKey.getEncoded().length, domain.length);
		System.arraycopy(username, 0, c, pubKey.getEncoded().length + domain.length, username.length);
		System.out.println(new String(c));
		newPass.put(new String(c), password);
	}

	public byte[] getMapValue(PublicKey pubKey, byte[] domain, byte[] username) throws UnsupportedEncodingException{
		byte[] c = new byte[pubKey.getEncoded().length + domain.length + username.length];
		System.arraycopy(pubKey.getEncoded(), 0, c, 0, pubKey.getEncoded().length);
		System.arraycopy(domain, 0, c, pubKey.getEncoded().length, domain.length);
		System.arraycopy(username, 0, c, pubKey.getEncoded().length + domain.length, username.length);
		byte[] password_retrieved = newPass.get(new String(c));
		System.out.println(new String(c));
		
		if(password_retrieved != null){
			return password_retrieved;
		}
		else {
			return null;
		}
	}

	private void setKeys(KeyStore ks, String alias, String password) {
		try {
			//Get the keys for the given alias.			
			pubKey = ks.getCertificate(alias).getPublicKey();
			privKey = (PrivateKey) ks.getKey(alias, password.toCharArray());
			System.out.println("Loaded keys from keystore with success");
		} catch (Exception e){
			e.printStackTrace();
			System.out.println("impossible to load keys from keystore to library");
		}

	}

	public KeyStore getKeyStore(String pass){ //created with "olaola" as password
		KeyStore ks = null;
		try { //If KeyStore file already exists
			FileInputStream fis = new FileInputStream("serverkeystorefile.jce");	//Open the KeyStore file
			ks = KeyStore.getInstance("JCEKS"); //Create an instance of KeyStore of type “JCEKS”
			ks.load(fis, pass.toCharArray()); //Load the key entries from the file into the KeyStore object.
			fis.close();
			System.out.println("KeyStore Loaded");
		} //create it if cannot find it
		catch (FileNotFoundException e) {	
			try { //Could not load KeyStore file, create one
				ks = KeyStore.getInstance("JCEKS");
				ks.load(null, pass.toCharArray()); // Create keystore 
				//Create a new file to store the KeyStore object
				java.io.FileOutputStream fos = new java.io.FileOutputStream("serverkeystorefile.jce");
				ks.store(fos, pass.toCharArray());
				//Write the KeyStore into the file
				fos.close();
				System.out.println("KeyStore Created");
			} catch (NoSuchAlgorithmException | CertificateException | IOException | KeyStoreException e1) {
				e1.printStackTrace();
			} 
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
		//Verifica se é repetido o publicKey
		if(registeredKeys.contains(msg.getPubKey())){
			Long nonce = getNounce();
			nounces.put(msg.getPubKey(), nonce);
			msg.setNounce(nonce);
			msg.setRes("used key");
			System.out.println("already registered, aborted");
			return msg;
		}
		else{
			Long nonce = getNounce();
			nounces.put(msg.getPubKey(), nonce);
			registeredKeys.add(msg.getPubKey());
			msg.setRes("success");
			msg.setNounce(nonce);
			return msg;
		}
	}

	public void	put(PublicKey publicKey, byte[] domain, byte[] username, byte[] password){ 
		System.out.println("Server executed: Save_password");
		putMap(publicKey, domain, username, password);

	}

	public byte[] get(PublicKey publicKey, byte[] domain, byte[] username){
		System.out.println("Server executed: Retrieve_password");
		byte[] pass = null;
		try {
			pass = getMapValue(publicKey, domain, username);
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return pass;
	}


	public String close(){
		System.out.println("Server executed: Close");
		return "Success";
	}

	public long getNounce(){
		long res = 0;
		try {
			SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
			res = random.nextLong();
			while(usedNounces.contains(res)){
				res = random.nextLong();
			}
			usedNounces.add(res);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return 0;
		}
		return res;
	}


	public static void main(String args[]){

		Server server = new Server();
		server.newPass = new HashMap<String, byte[]>();
		server.nounces = new HashMap<PublicKey, Long>();
		server.usedNounces = new ArrayList<Long>();
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
