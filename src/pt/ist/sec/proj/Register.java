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
	private Map<PublicKey, List<Long>> replaceNonces;
	
	static int numServers = 3;

	static boolean verbose = true;
	static int registerPort = 1025;
	static int initialServerPort = 1026;

	static Crypto crypto = new Crypto();

	public Register() {

	}

	public static void main(String args[]){

		Register register = new Register();
		register.expectedNonce = new HashMap<PublicKey, Long>();
		register.replaceNonces = new HashMap<PublicKey, List<Long>>();
;
		
		System.out.println("===== Register Started =====");
		
		try {
			registerSocket = new ServerSocket(registerPort);
			
			while(true){
				Socket libraryClient = registerSocket.accept();
				
				new RegisterThread(libraryClient, register).start();
				
			}

		} catch (IOException e) {
			e.printStackTrace();
		}

	}
	
	public void saveNonce(PublicKey pk, long n, byte[] sign){
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
	}
	
}
