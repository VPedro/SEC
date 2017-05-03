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
	boolean verbose = false;

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
			boolean valid = crypto.signature_verify(resMsg.getSignNonce(), resMsg.getPubKey(), resMsg.getNonce().toString().getBytes("UTF-8"));
			if(valid ){
				if(resMsg.getRes().equals("fail")){
					System.out.println("Get nonce failed");
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

		try {
			outObject.writeObject(msg);
			resMsg = (SignedMessage)inObject.readObject();
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
		byte[] sig_nonce;
		if(nonce!=null){
			sig_nonce = crypto.signature_generate(nonce.toString().getBytes(), privKey);
		}else{
			sig_nonce = null;
		}
		byte[] p = crypto.encrypt(password, pubKey);
		byte[] sig_p = crypto.signature_generate(p, privKey);
		return new Message(s, pubKey, sig_d, sig_u, sig_p, domain, username, p, nonce, sig_nonce);
	}

	public void save_password(byte[] domain, byte[] username, byte[] password) throws IOException {


		nextNonce = getNonce();
		byte[] hash_dom = crypto.hash_sha256(domain);
		byte[] hash_user = crypto.hash_sha256(username);
		Message msg = createMessage("save_password", hash_dom, hash_user, password, nextNonce);
		System.out.println("Sent save to register");
		SignedMessage resMsg = null;
		try {
			outObject.writeObject(msg);
			resMsg = (SignedMessage)inObject.readObject();
			if(verbose)
				System.out.println("Received result" + resMsg.getRes());

			if(resMsg.getRes().equals("register_fail")){
				System.out.println("You are not registered");
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
				System.out.println("Server signature not valid");
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
		System.out.println("Sent retrieve to register");
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
				System.out.println("No password found");
				return "fail";
			}else if(((SignedMessage) o).getRes().equals("no password")){
				System.out.println("No password found");
				return "fail";
			}
		}
		else{
			Message m = (Message)o;
			if(m == null){
				return null;
			}
			boolean ver_p = false;
			if(m.getPassword() != null) {
				ver_p = crypto.signature_verify(m.getSig_password(), m.getPublicKey(), m.getPassword());
			}
			else return null;
			if(ver_p){ 	

				byte[] b = crypto.decrypt(m.getPassword(), privKey);
				if (b == null){return null;}
				try {
					return new String(b, "UTF-8");
				} catch (UnsupportedEncodingException e) {
					e.printStackTrace();
				}
			}else{
				System.out.println("Password signature not valid");
			}
		}
		return null;
	}


	public void close(){

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
