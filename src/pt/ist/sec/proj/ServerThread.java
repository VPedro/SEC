package pt.ist.sec.proj;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.nio.ByteBuffer;
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
	
	public void sendAckMessage(String func, int ts){
		AckMessage msg = new AckMessage(func, ts);
		try {
			objOut.writeObject(msg);
		} catch (IOException e) {
			System.out.println("Error sending AckMessage ");
		}
	}
	
	public void sendSignedMessage(String func, PublicKey pubKey, byte[] sign, String res, byte[] value){
		SignedMessage msg = new SignedMessage(func,pubKey, sign, res, value, null, null);
		try {
			objOut.writeObject(msg);
		} catch (IOException e) {
			System.out.println("Error sending SignedMessage ");
		}
	}
	
	public boolean validMessageSignatures(RegisterMessage m, boolean wts, boolean dom, boolean user, boolean pass, boolean nonce){
		boolean valid0,valid1,valid2,valid3,valid4;
		valid0=valid1=valid2=valid3=valid4= true;
		
		if(wts){
			valid0 = crypto.signature_verify(m.getSignWTS(), m.getPubKey(), intToBytes(m.getWTS()));
		}
		if(dom){
			valid1 = crypto.signature_verify(m.getSignDomain(), m.getPubKey(), m.getDomain());
		}
		if(user){
			valid2 = crypto.signature_verify(m.getSignUsername(), m.getPubKey(), m.getUsername());
		}
		if(pass){
			valid3 = crypto.signature_verify(m.getSignPassword(), m.getPubKey(), m.getPassword());
		}
		if(nonce){
			//valid4 = crypto.signature_verify(m.getSig_nonce(), m.getPublicKey(), m.getNonce().toString().getBytes());
			valid4=true;
		}
		//FIXME
		
		return valid0 & valid1 & valid2 & valid3 & valid4 ;
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
			//valid4 = crypto.signature_verify(m.getSig_nonce(), m.getPublicKey(), m.getNonce().toString().getBytes());
			valid4=true;
		}
		//FIXME
		
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
				if (input instanceof RegisterMessage) {
					RegisterMessage rcvdMsg = (RegisterMessage)input;
					if(rcvdMsg.getFunc().equals("save_password")){
						if(validMessageSignatures(rcvdMsg,true, true,true,true,true)){
							if(verbose) {
								System.out.println("Aqui" );
							}
							//Long n_compare = server.getNonces().get(m.getPublicKey());
							//FIXME compare nonces
							/*if((long)n_compare != ((long)m.getNonce())){
								System.out.println("Different Nonce, reject"); 
								sendSignedMessage("invalid", pubKey, sign_pub, "invalid message", null);
								continue; 
							}*/
							System.out.println("DUP Signature verified successfully! (no yet...)");
							server.put(rcvdMsg.getPubKey(), rcvdMsg.getDomain(), rcvdMsg.getUsername(), rcvdMsg.getPassword());
							
							//FIXEME
							server.updateTS(rcvdMsg.getPubKey(), rcvdMsg.getWTS(),rcvdMsg.getPassword(), rcvdMsg.getSignPassword());
							sendAckMessage("save_password",rcvdMsg.getWTS());
							//sendSignedMessage("save_password", pubKey, sign_pub, "success", m.getPassword());
						} else {
							System.out.println("Signature not valid!");
							sendSignedMessage("save_password", pubKey, sign_pub, "fail", null);
						}
					}
				}
				else if(input instanceof SignedMessage) {
					SignedMessage m = (SignedMessage)input;

					boolean valid = crypto.signature_verify(m.getSign(), m.getPubKey(), m.getPubKey().getEncoded());
					SignedMessage resMsg;
					if(!valid){
						sendSignedMessage("invalid", pubKey, sign_pub,"invalid signature", null);
					}
					if(m.getFunc().equals("register")){	
						SignedMessage sm = server.register(m);
						sendSignedMessage("register", pubKey, sign_pub, sm.getRes(), null);
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
							if(verbose){
								System.out.println("GONNA SEND MY N0NCE");
							
								System.out.println(resMsg.getSignNonce());
								System.out.println(resMsg.getPubKey());
								System.out.println(resMsg.getNonce());
							}
							
							try {
								objOut.writeObject(resMsg);
							} catch (IOException e) {
								System.out.println("Error sending SignedMessage ");
							}
							
						}else{
							sendSignedMessage("nonce", pubKey, sign_pub, "fail", null);
						}
						
					}else if(m.getFunc().equals("update_nonce")){
						Long Nonce= server.getNonce();
						server.getNonces().put(m.getPubKey(), Nonce);
						
					}
					else if(m.getFunc().equals("close")){
						sendSignedMessage("close", pubKey, sign_pub, "closed", null);
						connectionOpen = false;
					}
				}
			} catch (ClassNotFoundException | IOException e) {
				System.out.println("Thread killed");
				connectionOpen = false;
			}
		}
	}
	
	public byte[] intToBytes( final int i ) {
	    ByteBuffer bb = ByteBuffer.allocate(4); 
	    bb.putInt(i); 
	    return bb.array();
	}
}
