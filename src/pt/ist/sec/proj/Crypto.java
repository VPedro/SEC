package pt.ist.sec.proj;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import sun.misc.*;
import java.util.Base64;

public class Crypto {

	public String base64encode(byte[] bytes){
		Base64.Encoder encoder = Base64.getEncoder();
		return encoder.encodeToString(bytes);
	}
	
	public byte[] base64decode(String s){
		Base64.Decoder decoder = Base64.getDecoder();
		return decoder.decode(s);
	}
	
	public byte[] compute_sha(byte[] bytes){
		byte[] hash = null;
		try {
			MessageDigest sha;
			sha = MessageDigest.getInstance("SHA-256");
			sha.update(bytes);
			hash = sha.digest();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return hash;
	}	
	
	public static void main(String args[]){
		Crypto c = new Crypto();
		
		String s1 = "o vasco é gay";
		System.out.println("Original Key: " + s1);
		
		byte[] hashed = c.compute_sha(s1.getBytes());
		System.out.println("Hashed String: " + hashed);
		
		String hashed_and_encoded = c.base64encode(hashed);
		System.out.println("Hashed and Decoded String: " + hashed_and_encoded);
	}
	
}










