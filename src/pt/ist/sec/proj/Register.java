package pt.ist.sec.proj;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
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


public class Register {

	private static Socket[] serverSockets;
	private static ServerSocket registerSocket;

	static ObjectInputStream libraryObjIn;
	static ObjectOutputStream libraryObjOut;

	static PublicKey pubKey;
	static PrivateKey privKey;
	
	private Map<PublicKey, Long> expectedNonce;
	private List<Long> usedNonces;
	//private Map<PublicKey, List<Long>> replaceNonces;
	
	
	static int numServers = 3;

	static boolean verbose = true;
	static int registerPort = 1025;
	static int initialServerPort = 1026;

	static Crypto crypto = new Crypto();
	
	/*
	 * register implementation
	 */
	static int regID; //é o bonrr?
	static int wts;
	SignedMessage[] ackSignedMsgs;
	Message[] ackMsgs;
	static int rid;
	String[] readList;
	
	public Register() {
		
		this.wts = 0;
		this.ackSignedMsgs = new SignedMessage[numServers];
		this.ackMsgs = new Message[numServers];
		this.rid = 0;
		this.readList = new String[numServers];
	}

	public static void main(String args[]){

		Register register = new Register();
		register.expectedNonce = new HashMap<PublicKey, Long>();
		register.usedNonces = new ArrayList<Long>();
		//register.replaceNonces = new HashMap<PublicKey, List<Long>>();

		KeyStore ks  = register.getKeyStore("olaola");
		register.setKeys(ks,"register","olaola");
		
		System.out.println("===== Register Started =====");
		try {
			registerSocket = new ServerSocket(registerPort);
			while(true){
				Socket libraryClient = registerSocket.accept();
				int regID = getRegID(); 
				new RegisterThread(regID,numServers, libraryClient, register).start();
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public static int getRegID(){
		regID++;
		return regID;
	}
	
	public int getWTS(){
		wts++;
		return wts;
	}
	
	public int getRID(){
		rid++;
		return rid;
	}
	
	
	
	
	public long getNonce(PublicKey pk){
		return expectedNonce.get(pk);
	}
	
	public void setNonce(PublicKey pk){
		long nonce = generateNonce();
		expectedNonce.put(pk, nonce);
		
	}

	public List<Long> getUsedNonces(){
		return usedNonces;
	}
	
	public long generateNonce(){
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
	
	PublicKey getPubKey() {
		return pubKey;
	}

	PrivateKey getPrivKey() {
		return privKey;
	}
	
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
			String path = "keystores/register.jce";
			FileInputStream fis = new FileInputStream(path);	//Open the KeyStore file
			ks = KeyStore.getInstance("JCEKS"); //Create an instance of KeyStore of type “JCEKS”
			ks.load(fis, pass.toCharArray()); //Load the key entries from the file into the KeyStore object.
			fis.close();
			System.out.println("Loaded register KeyStore ");
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
	
	
	/*
	 * below not used...
	 */
	/*public void saveNonce(PublicKey pk, long n, byte[] sign){
		if(replaceNonces.get(pk)==null){
			List<Long> list = new ArrayList<Long>();
			list.add(n);
			replaceNonces.put(pk,list);
			expectedNonce.put(pk, n);
		}else{
			replaceNonces.get(pk).add(n);
		}
		
	}

	public Long getExpectedNonce(PublicKey pk) {
		// TODO Auto-generated method stub
		return expectedNonce.get(pk);
	}*/
	
}
