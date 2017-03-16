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

	/*************************************** CLIENT ***************************************/
	private Socket client;
	ObjectOutputStream outObject;
	ObjectInputStream inObject;
	DataOutputStream outData;
	DataInputStream inData;

	static PublicKey pubKey;
	static PrivateKey privKey;

	private Long nextNounce;
	boolean verbose = false;

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

			if(!setKeys(keystore, alias, password))
				return false;

			nextNounce = getNonce();
			if(verbose) {
				System.out.println("Nonce: " + nextNounce);
			}

			return true;

		} catch (UnknownHostException e) {
			e.printStackTrace();
			return false;
		} catch (ConnectException e1) {
			System.out.println("Error initiating library, no server available");
			return false;
		} catch (IOException e) {
			e.printStackTrace();
			return false;
		}
	}


	private long getNonce() {		
		byte[] sig_pub = crypto.signature_generate(pubKey.getEncoded(), privKey);

		SignedMessage msg = new SignedMessage("nounce", pubKey, sig_pub,  null, null, null);
		SignedMessage resMsg = null;
		try {
			outObject.writeObject(msg);
			resMsg = (SignedMessage)inObject.readObject();

			boolean valid = crypto.signature_verify(resMsg.getSignNounce(), resMsg.getPubKey(),  resMsg.getNounce().toString().getBytes("UTF-8"));
			if(valid ){

				if(resMsg.getRes().equals("fail")){
					System.out.println("Could not save the password");
				}else{
					boolean validNounce = crypto.signature_verify(resMsg.getSignNounce(), resMsg.getPubKey(),  resMsg.getNounce().toString().getBytes("UTF-8"));
					if(validNounce){
						//save received nounce
						Long l = resMsg.getNounce();
						if(verbose) {
							System.out.println("Nonce received: " + l);
						}
						return l;

					}
				}
			}		
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		} catch (ClassNotFoundException e) {
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

		SignedMessage msg = new SignedMessage("register", pubKey, sig_pub, null, null, null);
		SignedMessage resMsg = null;
		try {
			outObject.writeObject(msg);
			resMsg = (SignedMessage)inObject.readObject();
			if(resMsg.getRes().equals("success")){
				boolean b = crypto.signature_verify(resMsg.getSignNounce(), resMsg.getPubKey(), resMsg.getNounce().toString().getBytes());
				if (b){
					nextNounce = resMsg.getNounce();
					if(verbose) {
						System.out.println("Next nonce: " + nextNounce);
					}
				}
				//long n = 0;
				//nextNounce = n;
				System.out.println("Registered in server with success");
				//return true;
			}else if(resMsg.getRes().equals("used key")){
				boolean b = crypto.signature_verify(resMsg.getSignNounce(), resMsg.getPubKey(), resMsg.getNounce().toString().getBytes());
				if (b){
					nextNounce = resMsg.getNounce();
					if(verbose) {
						System.out.println("Next nonce: " + nextNounce);
					}
				}
				System.out.println("You are already registered");
				//return false;
			}
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}
		//return false;	
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
		byte[] hash_dom = crypto.hash_sha256(domain);
		byte[] hash_user = crypto.hash_sha256(username);

		Message msg = createMessage("save_password", hash_dom, hash_user, password, nextNounce);
		SignedMessage resMsg = null;
		try {
			outObject.writeObject(msg);
			resMsg = (SignedMessage)inObject.readObject();
			if(resMsg.getRes().equals("register_fail")){
				System.out.println("You are not registered");
				return;
			}
			boolean valid = crypto.signature_verify(resMsg.getSign(), resMsg.getPubKey(), resMsg.getPubKey().getEncoded());
			if(valid){
				if(resMsg.getRes().equals("success")){
					System.out.println("Password saved with success");
					boolean validNounce = crypto.signature_verify(resMsg.getSignNounce(), resMsg.getPubKey(),  resMsg.getNounce().toString().getBytes("UTF-8"));
					if(validNounce){
						//save new nounce
						Long l = resMsg.getNounce();
						if(verbose) {
							System.out.println("Nonce received: " + l);
						}
						nextNounce = l;
						if(verbose) {
							System.out.println("Next nonce: " + nextNounce);
						}
					}
					else {
						System.out.println("Nonce not valid!");
					}
				}
				else{
					System.out.println("Error saving your password!");
				}
			}			
		} catch (IOException | ClassNotFoundException e) {
			e.printStackTrace();
			System.out.println("Could not save password!");
		}
	}

	public String retrieve_password(byte[] domain, byte[] username){
		byte[] hash_dom = crypto.hash_sha256(domain);
		byte[] hash_user = crypto.hash_sha256(username);

		Message msg = createMessage("retrieve_password", hash_dom, hash_user, null, nextNounce);
		Object o = null;
		try {
			outObject.writeObject(msg);
			o = (Object)inObject.readObject();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}
		if(o instanceof SignedMessage){
			if(((SignedMessage) o).getRes().equals("register_fail")){
				System.out.println("You are not registered!");
				return "fail";
			}
		}
		Message m = (Message)o;
		boolean ver_p = false, ver_n;
		if(m.getPassword() != null) {
			ver_p = crypto.signature_verify(m.getSig_password(), m.getPublicKey(), m.getPassword());
		}
		ver_n = crypto.signature_verify(m.getSig_nonce(), m.getPublicKey(), m.getNonce().toString().getBytes());
		nextNounce = m.getNonce();
		if(verbose) {
			System.out.println("Next nonce: " + nextNounce);
		}
		if(ver_p && ver_n){ 	
			nextNounce = m.getNonce();
			if(verbose) {
				System.out.println("Next nonce: " + nextNounce);
			}
			byte[] b = crypto.decrypt(m.getPassword(), privKey);
			if (b == null){return null;}
			try {
				return new String(b, "UTF-8");
			} catch (UnsupportedEncodingException e) {
				e.printStackTrace();
			}
		}
		return null;
	}


	public void close(){
		byte[] sig_pub = crypto.signature_generate(pubKey.getEncoded(), privKey);
		SignedMessage msg = new SignedMessage("close",pubKey, sig_pub,null, null, null);
		SignedMessage resMsg = null;
		try {
			outObject.writeObject(msg);
			resMsg = (SignedMessage)inObject.readObject();
			if(verbose) {
				System.out.println("Result from server: " + resMsg.getRes());
			}
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}
	}

}
