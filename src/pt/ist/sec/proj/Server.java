package pt.ist.sec.proj;

import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
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
	private Map<ArrayList<String>, String> passwords;
	//basta usar uma list de PublicKey.. que eu saiba é so ver se é repetida no register
	private Map<ArrayList<String>, PublicKey> publicKeys;
	private Map<PublicKey, Long> nounces;
	private List<Long> usedNounces;
	private List<PublicKey> pubKeys;
	private Crypto crypto;

	PublicKey pubKey;
	PrivateKey privKey;

	public PublicKey getKey(byte[] domain, byte[] username){
		ArrayList<String> list = new ArrayList<String>(); list.add(crypto.encode_base64(domain)); list.add(crypto.encode_base64(username));
		PublicKey key_retrieved = publicKeys.get(list);
		return key_retrieved;
	}

	public void putKey(byte[] domain, byte[] username, PublicKey publicKey){
		ArrayList<String> list = new ArrayList<String>(); list.add(crypto.encode_base64(domain)); list.add(crypto.encode_base64(username));
		publicKeys.put(list, publicKey);
	}

	public void putMap(PublicKey pubKey, byte[] domain, byte[] username, byte[] password){
		ArrayList<String> list = new ArrayList<String>();
		list.add(crypto.encode_base64(pubKey.getEncoded()));
		list.add(crypto.encode_base64(domain));
		list.add(crypto.encode_base64(username));
		passwords.put(list, crypto.encode_base64(password));
	}

	public byte[] getMapValue(PublicKey pubKey, byte[] domain, byte[] username) throws UnsupportedEncodingException{
		ArrayList<String> list = new ArrayList<String>();
		list.add(crypto.encode_base64(pubKey.getEncoded()));
		list.add(crypto.encode_base64(domain));
		list.add(crypto.encode_base64(username));
		String password_retrieved = passwords.get(list);
		if(password_retrieved != null){
			return crypto.decode_base64(password_retrieved);
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
		/* registers the user in the server. Anomalous or unauthorized
		 * requests should return an appropriate exception or error code
		 */

		//Verifica se é repetido o publicKey
		if(pubKeys.contains(msg.getPubKey())){
			msg.setRes("used key");
			System.out.println("already registered, aborted");
			return msg;
		}else{
			long nounce = getNounce();
			nounces.put(msg.getPubKey(), nounce);
			msg.setRes("success");
			return msg;
		}
		

	}

	public void	put(PublicKey publicKey, byte[] domain, byte[] username, byte[] password){ 
		System.out.println("Save_password received.");
		putMap(publicKey, domain, username, password);

	}

	public byte[] get(PublicKey publicKey, byte[] domain, byte[] username){
		System.out.println("Retrieve_password received.");
		byte[] pass = null;
		try {
			pass = getMapValue(publicKey, domain, username);
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return pass;
	}

	public String close(){
		System.out.println("close command received");
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
		server.crypto = new Crypto();
		server.passwords = new HashMap<ArrayList<String>, String>();
		server.nounces = new HashMap<PublicKey, Long>();
		server.usedNounces = new ArrayList<Long>();
		server.pubKeys = new ArrayList<PublicKey>();

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

}
