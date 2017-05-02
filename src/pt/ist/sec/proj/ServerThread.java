package pt.ist.sec.proj;

import java.io.EOFException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;


public class ServerThread extends Thread {

	private Socket socket;
	private Server server;
	Crypto crypto;
	static PublicKey pubKey;
	static PrivateKey privKey;
	byte[] sign_pub;
	
	ObjectInputStream objIn;
	ObjectOutputStream objOut;
	
	boolean verbose = true;

	public ServerThread(Socket clientSocket, Server server) {
		this.socket = clientSocket;
		this.server = server;
	}
	
	public void sendSignedMessage(String func, PublicKey pubKey, byte[] sign, String res, byte[] value){
		SignedMessage msg = new SignedMessage(func,pubKey, sign, res, value, null, null);
		try {
			objOut.writeObject(msg);
		} catch (IOException e) {
			System.out.println("Error sending SignedMessage ");
		}
	}
	
	public boolean validMessageSignatures(Message m, boolean dom, boolean user, boolean pass, boolean nonce){
		boolean valid1,valid2,valid3,valid4;
		valid1=valid2=valid3=valid4= true;
		
		if(dom){
			valid1 = crypto.signature_verify(m.getSig_domain(), m.getPublicKey(), m.getDomain());
		}
		if(user){
			valid2 = crypto.signature_verify(m.getSig_username(), m.getPublicKey(), m.getUsername());
		}
		if(pass){
			valid3 = crypto.signature_verify(m.getSig_password(), m.getPublicKey(), m.getPassword());
		}
		if(nonce){
			valid4 = crypto.signature_verify(m.getSig_nonce(), m.getPublicKey(), m.getNonce().toString().getBytes());
		}
		return valid1 & valid2 & valid3 & valid4 ;
	}

	public void run() {
		objIn = null;
		objOut = null;
		crypto = new Crypto();
		try {
			objIn = new ObjectInputStream(socket.getInputStream());
			objOut = new ObjectOutputStream(socket.getOutputStream());
		} catch (IOException e) {
			System.out.println("IOException");;
		}
		Object input;
		pubKey = server.getPubKey();
		privKey = server.getPrivKey();
		sign_pub = crypto.signature_generate(pubKey.getEncoded(), privKey);
		boolean connectionOpen = true;
		while (connectionOpen) {
			try {
				input = objIn.readObject();
				if (input instanceof Message) {
					Message m = (Message)input;
					SignedMessage resMsg;
					if(!server.getRegisteredKeys().contains(m.getPublicKey())){
						System.out.println("Please Register first!");
						resMsg = new SignedMessage(null,pubKey,sign_pub ,"register_fail", null, null, null);
						objOut.writeObject(resMsg);
						continue;
					}
					if(m.getFunctionName().equals("save_password")){
						if(validMessageSignatures(m,true,true,true,true)){
							if(verbose) {
								System.out.println("Expected nonce: " + server.getNonces().get(m.getPublicKey()));
								System.out.println("Nonce received by server: " + m.getNonce());
							}
							Long n_compare = server.getNonces().get(m.getPublicKey());
							if((long)n_compare != ((long)m.getNonce())){
								System.out.println("Different Nonce, reject"); 
								continue; 
							}
							System.out.println("DUP Signature verified successfully!");
							server.put(m.getPublicKey(), m.getDomain(), m.getUsername(), m.getPassword());
							sendSignedMessage(null, pubKey, sign_pub, "success", m.getPassword());
						} else {
							System.out.println("Signature not valid!");
							sendSignedMessage(null, pubKey, sign_pub, "fail", null);
						}
					}
					else if(m.getFunctionName().equals("retrieve_password")){
						if(validMessageSignatures(m, true, true, false, true)) {
							Long n_compare = server.getNonces().get(m.getPublicKey());
							if(verbose) {
								System.out.println("Compare " + n_compare + " " + m.getNonce());
							}
							if((long)n_compare != (long)m.getNonce()){ 
								System.out.println("Repeated Nonce, possible replay attack");
								//TODO
								sendSignedMessage(null, pubKey, sign_pub, "invalid message", null);
							}
							System.out.println("Signature verified successfully!");
							
							byte[] pass = server.get(m.getPublicKey(), m.getDomain(), m.getUsername());
							Message m2 = new Message(null, pubKey, null, null, crypto.signature_generate(pass, privKey), null, null, pass, null, null); 
							objOut.writeObject(m2);
						}
						else {
							System.out.println("Signature not valid!");
							//TODO
							//sendSignedMessage(null, pubKey, sign_pub, "invalid message");
						}
					}
				}
				else if(input instanceof SignedMessage) {
					SignedMessage m = (SignedMessage)input;

					boolean valid = crypto.signature_verify(m.getSign(), m.getPubKey(), m.getPubKey().getEncoded());
					SignedMessage resMsg;
					if(!valid){
						sendSignedMessage(null, pubKey, sign_pub,"invalid signature", null);
					}
					if(m.getFunc().equals("register")){	
						SignedMessage sm = server.register(m);
						sendSignedMessage(null, pubKey, sign_pub, sm.getRes(), null);
					}else if(m.getFunc().equals("nonce")){
						Long Nonce= server.getNonce();
						server.getNonces().put(m.getPubKey(), Nonce);
						if(verbose) {
						System.out.println("Genereated nonce: " + Nonce);
						}
						if(Nonce != 0){
							if(verbose) {
							System.out.println("Nonce that is going to be send: "+Nonce.toString());
							}
							byte[] sign_Nonce = crypto.signature_generate(Nonce.toString().getBytes("UTF-8"), privKey);
							resMsg = new SignedMessage("nonce",pubKey,sign_pub, "success", null, Nonce, sign_Nonce);
							System.out.println("GONNA SEND MY N0NCE");
							System.out.println(resMsg.getSignNonce());
							System.out.println(resMsg.getPubKey());
							System.out.println(resMsg.getNonce());
							objOut.writeObject(resMsg);
						}else{
							sendSignedMessage(null, pubKey, sign_pub, "fail", null);
						}
						
					}else if(m.getFunc().equals("close")){
						sendSignedMessage(null, pubKey, sign_pub, "closed", null);
						connectionOpen = false;
					}
				}
			} catch (ClassNotFoundException | IOException e) {
				System.out.println("Thread killed");
				connectionOpen = false;
			}
		}
	}
}
