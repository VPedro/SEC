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

	//TODO func update nonce 

	private ServerSocket serverSocket;
	//FIXME estrutura q guarda a signature para cada pass recebida e garante nao repudio
	private Map<String, List<byte[]>> newPass;
	private Map<PublicKey, Long> nonces;
	private List<PublicKey> registeredKeys;
	private List<Long> usedNonces;
	boolean verbose = true;
	static int port = 1026;
	static int ServerID;

	private Map<PublicKey, Integer> PubKeyTS;
	private Map<Integer, byte[]> TSValues;
	private Map<Integer, byte[]> TSSigns;

	public Server(String string) {
		ServerID = Integer.parseInt(string);
	}

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
			String path = "keystores/server" +ServerID + ".jce";
			FileInputStream fis = new FileInputStream(path);	//Open the KeyStore file
			ks = KeyStore.getInstance("JCEKS"); //Create an instance of KeyStore of type “JCEKS”
			ks.load(fis, pass.toCharArray()); //Load the key entries from the file into the KeyStore object.
			fis.close();
			System.out.println("Loaded KeyStore "+ServerID);
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
			System.out.println("Registered with success");
			return msg;
		}
	}


	public void	put(PublicKey publicKey, byte[] domain, byte[] username, byte[] password){ 
		System.out.println("Server executed: Save_password");
		byte[] c = new byte[publicKey.getEncoded().length + domain.length + username.length];
		System.arraycopy(publicKey.getEncoded(), 0, c, 0, publicKey.getEncoded().length);
		System.arraycopy(domain, 0, c, publicKey.getEncoded().length, domain.length);
		System.arraycopy(username, 0, c, publicKey.getEncoded().length + domain.length, username.length);
		//newPass.put(new String(c), password);
		String key = new String(c);
		if(newPass.get(key)==null){
			List<byte[]> pass = new ArrayList<byte[]>();
			newPass.put(key,pass);
		}
		newPass.get(key).add(password);
	}

	public byte[] get(PublicKey publicKey, byte[] domain, byte[] username){
		System.out.println("Server executed: Retrieve_password");

		byte[] c = new byte[publicKey.getEncoded().length + domain.length + username.length];
		System.arraycopy(publicKey.getEncoded(), 0, c, 0, publicKey.getEncoded().length);
		System.arraycopy(domain, 0, c, publicKey.getEncoded().length, domain.length);
		System.arraycopy(username, 0, c, publicKey.getEncoded().length + domain.length, username.length);
		List<byte[]> list = newPass.get(new String(c));
		System.out.println("key: " + c);
		if(list == null){
			System.out.println("list de pass vazia:");
			return null;
		}

		byte[] password_retrieved = newPass.get(new String(c)).get(list.size()-1);
		if(password_retrieved != null){
			System.out.println("value:"+ password_retrieved);
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
			//enviar para a library que vai dar update a todos os servers (used nounces)

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return 0;
		}
		return res;
	}

	public static ServerSocket create(int min, int max) throws IOException {
		for (port=min; port <= max; port++) {
			try {
				System.out.println("Port:" + port);
				return new ServerSocket(port);
			} catch (IOException e) {
				continue; // try next port
			}
		}
		// if the program gets here, no port in the range was found
		throw new IOException("No free port found");
	}




	public static void main(String args[]){


		Server server = new Server(args[0]);
		server.newPass = new HashMap<String, List<byte[]>>();
		server.nonces = new HashMap<PublicKey, Long>();
		server.usedNonces = new ArrayList<Long>();
		server.registeredKeys = new ArrayList<PublicKey>();

		server.PubKeyTS =  new HashMap<PublicKey, Integer>();
		server.TSValues = new HashMap<Integer, byte[]>();
		server.TSSigns = new HashMap<Integer, byte[]>();

		KeyStore ks  = server.getKeyStore("olaola");
		server.setKeys(ks,"server","olaola");

		System.out.println("===== Server Started =====");
		Socket serverClient = null;

		try {
			server.serverSocket = create(port, port+5);			
			while(true){
				serverClient = server.serverSocket.accept();
				System.out.println("Started thread on port " + port);
				new ServerThread(serverClient, server).start();
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	

	public void updateTS(PublicKey pk, int ts, byte[] domain, byte[] username, byte[]password , byte[] signPass){
		//TODO if(rcvdMsg.getWTS() > server.get())

		Integer savedTS = PubKeyTS.get(pk);
		if(savedTS == null){
			PubKeyTS.put(pk, ts);
			put(pk, domain, username, password);
			TSValues.put(ts, password);
			TSSigns.put(ts, signPass);
		}else if(ts > savedTS){
			//TSValues.put(ts, value);
			TSSigns.put(ts, signPass);
			TSValues.put(ts, password);
			TSSigns.put(ts, signPass);

			//noa repudio
			//prova da assinada pelo cliente
			//TSSigns.put(ts, sign);
			
			put(pk, domain, username, password);


		}else{
			System.out.println("old version, ignnored");
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

	public int getLastTS(PublicKey clientPubKey) {
		return PubKeyTS.get(clientPubKey);
		
	}

}
