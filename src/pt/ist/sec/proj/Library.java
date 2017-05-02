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
import java.util.HashMap;
import java.util.Map;


public class Library {

	/*************************************** clients ***************************************/
	private Socket[] clients;
	ObjectOutputStream[] outObject;
	ObjectInputStream[] inObject;
	DataOutputStream[] outData;
	DataInputStream[] inData;
	int numServers = 5;

	static PublicKey pubKey;
	static PrivateKey privKey;

	private Long[] nextNonce;
	boolean verbose = true;

	Crypto crypto;

	public boolean init(KeyStore keystore, String alias, String password){

		String serverName = "localhost";
		int serverPort = 1025;
		crypto = new Crypto();
		clients = new Socket[numServers];
		outObject = new ObjectOutputStream[numServers];
		inObject = new ObjectInputStream[numServers];
		outData = new DataOutputStream[numServers];
		inData = new DataInputStream[numServers];

		nextNonce = new Long[numServers];

		for(int i=0; i<numServers; i++) {
			try {
				System.out.println("i = " + i);
				clients[i] = new Socket(serverName, serverPort+i);
				outObject[i] = new ObjectOutputStream(clients[i].getOutputStream());
				inObject[i] = new ObjectInputStream(clients[i].getInputStream());
				outData[i] = new DataOutputStream(clients[i].getOutputStream());
				inData[i] = new DataInputStream(clients[i].getInputStream());

				if(!setKeys(keystore, alias, password))
					return false;

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
		return true;
	}


	private long getNonce(int serverID) {		
		byte[] sig_pub = crypto.signature_generate(pubKey.getEncoded(), privKey);

		SignedMessage msg = new SignedMessage("nonce", pubKey, sig_pub, null, null, null, null);
		SignedMessage resMsg = null;
		try {
			outObject[serverID].writeObject(msg);
			resMsg = (SignedMessage)inObject[serverID].readObject();
			System.out.println("PROBLEMS");
			//TODO
			//ESTA MERDA POR ALGUMA RAZÃO ESTÁ A RECEBER O SIGNNONCE E NONCE A NULL, NO SEGUNDO SAVE
			System.out.println(resMsg.getSignNonce());
			System.out.println(resMsg.getPubKey());
			System.out.println(resMsg.getNonce());

			boolean valid = crypto.signature_verify(resMsg.getSignNonce(), resMsg.getPubKey(),  resMsg.getNonce().toString().getBytes("UTF-8"));
			if(valid ){
				if(resMsg.getRes().equals("fail")){
					System.out.println("Could not save the password");
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
		for(int i=0 ; i<numServers; i++) {
			try {
				outObject[i].writeObject(msg);
				resMsg = (SignedMessage)inObject[i].readObject();
				if(resMsg.getRes().equals("success")){
					System.out.println("Registered in server with success");
				}else if(resMsg.getRes().equals("used key")){
					System.out.println("You are already registered");
				}
			} catch (IOException | ClassNotFoundException e) {
				e.printStackTrace();
			}
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

		String[] resAnswers = new String[numServers];
		byte[][] valueAnswers = new byte[numServers][];
		HashMap<String,Integer> majority = new HashMap<String, Integer>();
		int ackCount = 0;

		//TODO
		//Timestamp timestamp = new Timestamp(System.currentTimeMillis());

		for(int i=0 ; i<numServers; i++) {
			nextNonce[i] = getNonce(i);
			byte[] hash_dom = crypto.hash_sha256(domain);
			byte[] hash_user = crypto.hash_sha256(username);
			Message msg = createMessage("save_password", hash_dom, hash_user, password, nextNonce[i]);
			SignedMessage resMsg = null;
			try {
				outObject[i].writeObject(msg);
				resMsg = (SignedMessage)inObject[i].readObject();
				ackCount++;
				resAnswers[i] = resMsg.getRes();
				valueAnswers[i] = crypto.decrypt(resMsg.getValue(), privKey);

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
				//e.printStackTrace();
				System.out.println("Could not save password!");
			}
		}

		//Verify if ackCount > N/2
		if(ackCount < (numServers / 2)) {
			System.out.println("Failed to save password, number of acks < N/2");
			//TODO
			return;
		}
		
		//this is where we verify the answers from the servers
		for(int i=0 ; i<numServers; i++) {
			if(resAnswers[i] == null && valueAnswers[i] == null) {
				continue;
			}
			if(majority.get(new String(valueAnswers[i], "UTF-8")) == null) {
				majority.put(new String(valueAnswers[i], "UTF-8"), 1);
			}
			majority.put(new String(valueAnswers[i], "UTF-8"), majority.get(new String(valueAnswers[i], "UTF-8")) +1);
		}

		if(verbose) {
			System.out.println("RECEIVED THIS:");
			for(int i=0 ; i<numServers; i++) {
				if(resAnswers[i] == null && valueAnswers[i] == null) {
					continue;
				}
				System.out.println("Result: " + resAnswers[i]);
				System.out.println("Password received: " + new String(valueAnswers[i], "UTF-8"));
			}
		}

		int frequency = 0;
		String key = "";

		for(Map.Entry<String, Integer> e : majority.entrySet()) {
			if(e.getValue() > frequency) {
				key = e.getKey();
				frequency = e.getValue();
			}
		}
		System.out.println("Most frequent answer: " + key);

		//Resend the most frequent answer to update all servers
		for(int i=0 ; i<numServers; i++) {
			nextNonce[i] = getNonce(i);
			byte[] hash_dom = crypto.hash_sha256(domain);
			byte[] hash_user = crypto.hash_sha256(username);
			Message msg = createMessage("save_password", hash_dom, hash_user, key.getBytes(), nextNonce[i]);
			outObject[i].writeObject(msg);
			try {
				//TODO
				//We want to ignore this return message from each server
				SignedMessage ignoreMsg = (SignedMessage)inObject[i].readObject();
			} catch (ClassNotFoundException e1) {
				e1.printStackTrace();
			}
		}

	}

	public String retrieve_password(byte[] domain, byte[] username){
		System.out.println(nextNonce[0]);
		System.out.println(nextNonce[1]);
		System.out.println(nextNonce[2]);
		for(int i=0 ; i<numServers; i++) {
			nextNonce[i] = getNonce(i);

			byte[] hash_dom = crypto.hash_sha256(domain);
			byte[] hash_user = crypto.hash_sha256(username);
			System.out.println("Sending to server number: " + i);
			Message msg = createMessage("retrieve_password", hash_dom, hash_user, null, nextNonce[i]);
			Object o = null;
			try {
				outObject[i].writeObject(msg);
				o = (Object)inObject[i].readObject();
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
			//TODO fazer as verificaçoes como no serverThred? com um func
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
		}
		return null;
	}


	public void close(){
		for(int i=0 ; i<numServers; i++) {
			nextNonce[i] = getNonce(i);
			//FIXME falta enviar o nonce e verificar do lado do server

			byte[] sig_pub = crypto.signature_generate(pubKey.getEncoded(), privKey);
			sendSignedMessage(i, "close", pubKey, sig_pub, null, null);
			try {
				SignedMessage resMsg = (SignedMessage)inObject[i].readObject();
				if(verbose) {
					System.out.println("Result from server: " + resMsg.getRes());
				}
			} catch (IOException | ClassNotFoundException e) {
				System.out.println("could not close in server");
			}
		}
	}

	public void sendSignedMessage(int serverID, String func, PublicKey pubKey, byte[] sign, Long nonce, byte[] signNonce){
		SignedMessage msg = new SignedMessage(func,pubKey, sign, null, null, nonce, signNonce);
		try {
			outObject[serverID].writeObject(msg);
		} catch (IOException e) {
			System.out.println("Error sending SignedMessage");
		}
	}

}
