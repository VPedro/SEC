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
	
	static PublicKey pubKey;
	static PrivateKey privKey;
	byte[] sign_pub;

	public ServerThread(Socket clientSocket, Server server) {
		this.socket = clientSocket;
		this.server = server;
	}

	public void run() {
		ObjectInputStream objIn = null;
		ObjectOutputStream objOut = null;
		Crypto crypto = new Crypto();
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
		boolean ver_d, ver_u, ver_p, ver_n;
		while (connectionOpen) {
			try {
				ver_d = true;
				ver_u = true;
				ver_p = true;
				input = objIn.readObject();
				if (input instanceof Message) {
					Message m = (Message)input;
					SignedMessage resMsg;
					if(!server.getRegisteredKeys().contains(m.getPublicKey())){
						System.out.println("Please Register first!");
						resMsg = new SignedMessage("nounce",pubKey,sign_pub ,"register_fail", null, null);
						objOut.writeObject(resMsg);
						continue;
					}
					if(m.getFunctionName().equals("save_password")){
						ver_d = crypto.signature_verify(m.getSig_domain(), m.getPublicKey(), m.getDomain());
						ver_u = crypto.signature_verify(m.getSig_username(), m.getPublicKey(), m.getUsername());
						ver_p = crypto.signature_verify(m.getSig_password(), m.getPublicKey(), m.getPassword());
						ver_n = crypto.signature_verify(m.getSig_nonce(), m.getPublicKey(), m.getNonce().toString().getBytes());
						if(ver_d && ver_u && ver_p && ver_n){
							System.out.println("EXPECTED NONCE: " + server.getNounces().get(m.getPublicKey()));
							System.out.println("NONCE: " + m.getNonce());
							Long n_compare = server.getNounces().get(m.getPublicKey());
							if((long)n_compare != ((long)m.getNonce())){ System.out.println("Different Nonce, reject"); continue; }
							System.out.println("DUP Signature verified successfully!");
							server.put(m.getPublicKey(), m.getDomain(), m.getUsername(), m.getPassword());	
							
							Long nounce = server.getNounce();
							System.out.println("GENERATED NONCE: " + nounce);
							server.getNounces().put(m.getPublicKey(), nounce);
							if(nounce != 0){							
								System.out.println("nouce that is going to be send: "+ nounce.toString());
								byte[] sign_nounce = crypto.signature_generate(nounce.toString().getBytes("UTF-8"), privKey);								
								resMsg = new SignedMessage("register", pubKey, sign_pub, "success", nounce, sign_nounce);
								objOut.writeObject(resMsg);
							}else{
								System.out.println("error generating nounce (serverThread)");
								resMsg = new SignedMessage("register", pubKey, sign_pub, "fail", null, null);
								objOut.writeObject(resMsg);
							}
						} else {
							System.out.println("Signature not valid!");
							resMsg = new SignedMessage("register", pubKey, sign_pub, "fail", null, null);
							objOut.writeObject(resMsg);
						}
					}
					else if(m.getFunctionName().equals("retrieve_password")){
						ver_d = crypto.signature_verify(m.getSig_domain(), m.getPublicKey(), m.getDomain());
						ver_u = crypto.signature_verify(m.getSig_username(), m.getPublicKey(), m.getUsername());
						ver_n = crypto.signature_verify(m.getSig_nonce(), m.getPublicKey(), m.getNonce().toString().getBytes());
						if(ver_d && ver_u && ver_n) {
							Long n_compare = server.getNounces().get(m.getPublicKey()); 
							System.out.println(n_compare + " " + m.getNonce());
							if((long)n_compare != (long)m.getNonce()){ System.out.println("Repeated Nonce, possible replay attack"); continue; }
							System.out.println("Signature verified successfully!");
							Long nonce = server.getNounce();
							server.getNounces().put(m.getPublicKey(), nonce);
							System.out.println("GENERATED NONCE: " + nonce);
							byte[] pass = server.get(m.getPublicKey(), m.getDomain(), m.getUsername());
							Message m2 = new Message(null, pubKey, null, null, crypto.signature_generate(pass, privKey), null, null, pass, nonce, crypto.signature_generate(nonce.toString().getBytes(), privKey)); 
							objOut.writeObject(m2);
						}
						else {
							System.out.println("Signature not valid!");
							resMsg = new SignedMessage("register", pubKey, sign_pub, "Regitered with success", null, null);
							objOut.writeObject(resMsg);
						}
					}
				}
				else if(input instanceof SignedMessage) {
					SignedMessage m = (SignedMessage)input;

					boolean valid = crypto.signature_verify(m.getSign(), m.getPubKey(), m.getPubKey().getEncoded());
					SignedMessage resMsg;
					if(!valid){
						resMsg = new SignedMessage("register", pubKey, sign_pub, "error signature", null, null);
						objOut.writeObject(resMsg);
					}
					if(m.getFunc().equals("register")){	
						SignedMessage sm = server.register(m);
						String result = sm.getRes();
						Long nounce = sm.getNounce();
						if(result.equals("success")){
							System.out.println("Signature verified successfully!");
							//Long nonce = server.getNounce(); 
							System.out.println("GENERATED NONCE: " + nounce);
							byte[] sig_nonce = crypto.signature_generate(nounce.toString().getBytes(), server.privKey);
							resMsg = new SignedMessage("register", pubKey, sign_pub, "success", nounce, sig_nonce);
							objOut.writeObject(resMsg);
						}else if (result.equals("used key")){
							//Long nonce = server.getNounce(); 
							System.out.println("GENERATED NONCE: " + nounce);
							byte[] sig_nonce = crypto.signature_generate(nounce.toString().getBytes(), server.privKey);
							resMsg = new SignedMessage("register",pubKey,sign_pub ,"used key", nounce, sig_nonce);
							objOut.writeObject(resMsg);
						}
					}else if(m.getFunc().equals("nounce")){
						Long nounce= server.getNounce();
						server.getNounces().put(m.getPubKey(), nounce);
						System.out.println("GENERATED NONCE: " + nounce);
						if(nounce != 0){							
							System.out.println("nouce that is going to be send: "+nounce.toString());
							byte[] sign_nounce = crypto.signature_generate(nounce.toString().getBytes("UTF-8"), privKey);
							resMsg = new SignedMessage("nounce",pubKey,sign_pub, "success", nounce, sign_nounce);
							objOut.writeObject(resMsg);
						}else{
							resMsg = new SignedMessage("nounce",pubKey,sign_pub ,"fail", null, null);
							objOut.writeObject(resMsg);
						}
						
					}else if(m.getFunc().equals("close")){
						resMsg = new SignedMessage("close",pubKey, sign_pub,"closed", null, null);
						objOut.writeObject(resMsg);
						connectionOpen = false;
						server.close();	
					}
				}/*else if(input==null){
					server.close();
				}*/
			} catch (ClassNotFoundException e) {
				e.printStackTrace();
				connectionOpen = false;
			} catch (EOFException e) {
				//e.printStackTrace();
				System.out.println("Exiting");
				connectionOpen = false;
				//System.exit(0);
			} catch (IOException e) {
				//e.printStackTrace();
				System.out.println("Exiting");
				connectionOpen = false;
			}
		}
	}

}
