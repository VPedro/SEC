package pt.ist.sec.proj;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.net.ConnectException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.*;


public class Library {

	/*************************************** clients ***************************************/
	private Socket registerSocket;
	ObjectOutputStream outObject;
	ObjectInputStream inObject;
	DataOutputStream outData;
	DataInputStream inData;

	static PublicKey pubKey;
	static PrivateKey privKey;

	private Long nextNonce;
	boolean verbose = true;

	Crypto crypto;

	public boolean init(KeyStore keystore, String alias, String password){

		String registerName = "localhost";
		int registerPort = 1025;
		crypto = new Crypto();
		registerSocket = new Socket();

		nextNonce = null;

		try {
			registerSocket = new Socket(registerName, registerPort);
			outObject = new ObjectOutputStream(registerSocket.getOutputStream());
			inObject = new ObjectInputStream(registerSocket.getInputStream());
			outData = new DataOutputStream(registerSocket.getOutputStream());
			inData = new DataInputStream(registerSocket.getInputStream());

			System.out.println("RNDDASDA");
			
			if(!setKeys(keystore, alias, password))
				return false;

		} catch (UnknownHostException e) {
			e.printStackTrace();
			return false;
		} catch (ConnectException e1) {
			System.out.println("Error initiating library, no register available");
			return false;
		} catch (IOException e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}


	private long getNonce() {		
		byte[] sig_pub = crypto.signature_generate(pubKey.getEncoded(), privKey);

		SignedMessage msg = new SignedMessage("nonce", pubKey, sig_pub, null, null, null, null);
		SignedMessage resMsg = null;

		try {
			outObject.writeObject(msg);
			resMsg = (SignedMessage)inObject.readObject();

			System.out.println(resMsg.getSignNonce() );
			System.out.println(resMsg.getPubKey());
			System.out.println(resMsg.getNonce().toString().getBytes("UTF-8"));
			boolean valid = crypto.signature_verify(resMsg.getSignNonce(), resMsg.getPubKey(),  resMsg.getNonce().toString().getBytes("UTF-8"));
			if(valid ){
				if(resMsg.getRes().equals("fail")){
					System.out.println("failed");
				}else{
					boolean validNounce = crypto.signature_verify(resMsg.getSignNonce(), resMsg.getPubKey(),  resMsg.getNonce().toString().getBytes("UTF-8"));
					if(validNounce){
						Long l = resMsg.getNonce();
						if(verbose) {
							System.out.println("Nonce received: " + l);
						}
						return l;
					}
				}
			}		
		} catch (IOException | ClassNotFoundException e) {
			e.printStackTrace();
			return 0;
		}
		return 0;
	}


	private boolean setKeys(KeyStore ks, String alias, String password) {
		try {
			//Get the keys for the given alias and password.			
			privKey = (PrivateKey) ks.getKey(alias, password.toCharArray());
			pubKey = ks.getCertificate(alias).getPublicKey();
			return true;
		} catch (Exception e){
			e.printStackTrace();
			System.out.println("Impossible to load keys from keystore to library");
			return false;
		}

	}


	public void register_user(){

		byte[] sig_pub = crypto.signature_generate(pubKey.getEncoded(), privKey);
		SignedMessage msg = new SignedMessage("register", pubKey, sig_pub, null, null, null, null);
		SignedMessage resMsg = null;

		System.out.println("0");
		try {
			System.out.println("1");

			outObject.writeObject(msg);
			resMsg = (SignedMessage)inObject.readObject();
			System.out.println("2");
			if(resMsg.getRes().equals("success")){
				
				System.out.println("Registered in server with success");
			}else if(resMsg.getRes().equals("used key")){
				System.out.println("You are already registered");
			}
		} catch (IOException | ClassNotFoundException e) {
			e.printStackTrace();
		}
	}

	public Message createMessage(String s, byte[] domain, byte[] username, byte[] password, Long nonce) {
		byte[] sig_d = crypto.signature_generate(domain, privKey);
		byte[] sig_u = crypto.signature_generate(username, privKey);
		byte[] sig_nonce = crypto.signature_generate(nonce.toString().getBytes(), privKey);
		byte[] p = crypto.encrypt(password, pubKey);
		byte[] sig_p = crypto.signature_generate(p, privKey);
		return new Message(s, pubKey, sig_d, sig_u, sig_p, domain, username, p, nonce, sig_nonce);
	}

	public void save_password(byte[] domain, byte[] username, byte[] password) throws IOException {

		//
		nextNonce = getNonce();
		byte[] hash_dom = crypto.hash_sha256(domain);
		byte[] hash_user = crypto.hash_sha256(username);
		Message msg = createMessage("save_password", hash_dom, hash_user, password, nextNonce);
		SignedMessage resMsg = null;
		try {
			outObject.writeObject(msg);
			resMsg = (SignedMessage)inObject.readObject();

			if(resMsg.getRes().equals("register_fail")){
				System.out.println("You are not registered");
				//return;
			}

			boolean valid = crypto.signature_verify(resMsg.getSign(), resMsg.getPubKey(), resMsg.getPubKey().getEncoded());
			if(valid){
				if(resMsg.getRes().equals("success")){
					System.out.println("Password saved with success");
				}
				else{
					System.out.println("Error saving your password!");
				}
			}else{
				System.out.println("server signature not valid");
			}
		} catch (IOException | ClassNotFoundException e) {
			System.out.println("Could not save password!");
		}
	}

	public String retrieve_password(byte[] domain, byte[] username){

		nextNonce = getNonce();

		byte[] hash_dom = crypto.hash_sha256(domain);
		byte[] hash_user = crypto.hash_sha256(username);
		Message msg = createMessage("retrieve_password", hash_dom, hash_user, null, nextNonce);
		Object o = null;
		try {
			outObject.writeObject(msg);
			o = (Object)inObject.readObject();
		} catch (IOException | ClassNotFoundException e) {
			e.printStackTrace();
		}
		if(o instanceof SignedMessage){
			if(((SignedMessage) o).getRes().equals("register_fail")){
				System.out.println("You are not registered!");
				return "fail";
			}else if(((SignedMessage) o).getRes().equals("invalid message")){
				System.out.println("the message was invalid");
				return "fail";
			}
		}

		Message m = (Message)o;
		boolean ver_p = false;
		if(m.getPassword() != null) {
			ver_p = crypto.signature_verify(m.getSig_password(), m.getPublicKey(), m.getPassword());
		}
		if(ver_p){ 	

			byte[] b = crypto.decrypt(m.getPassword(), privKey);
			if (b == null){return null;}
			try {
				System.out.println(new String(b, "UTF-8"));
				//return new String(b, "UTF-8");
			} catch (UnsupportedEncodingException e) {
				if(verbose) {
					System.out.println("Password store on server: " );
					e.printStackTrace();
				}
			}
		}else{
			System.out.println("password signature not valid");
		}

		return null;
	}


	public void close(){
		//TODO apagar do map pubkey, nonce
		
		/*nextNonce = getNonce();
		//FIXME falta enviar o nonce e verificar do lado do server

		byte[] sig_pub = crypto.signature_generate(pubKey.getEncoded(), privKey);
		sendSignedMessage("close", pubKey, sig_pub, null, null);
		try {
			SignedMessage resMsg = (SignedMessage)inObject.readObject();
			if(verbose) {
				System.out.println("Result from server: " + resMsg.getRes());
			}
		} catch (IOException | ClassNotFoundException e) {
			System.out.println("could not close in server");
		}*/
	}

	public void sendSignedMessage(String func, PublicKey pubKey, byte[] sign, Long nonce, byte[] signNonce){
		SignedMessage msg = new SignedMessage(func,pubKey, sign, null, null, nonce, signNonce);
		try {
			outObject.writeObject(msg);
		} catch (IOException e) {
			System.out.println("Error sending SignedMessage");
		}
	}
	
	
}
