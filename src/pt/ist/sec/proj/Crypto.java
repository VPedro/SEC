package pt.ist.sec.proj;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;

public class Crypto {

	public String encode_base64(byte[] bytes){
		Base64.Encoder encoder = Base64.getEncoder();
		return encoder.encodeToString(bytes);
	}
	
	public byte[] decode_base64(String s){
		Base64.Decoder decoder = Base64.getDecoder();
		return decoder.decode(s);
	}
	
	public byte[] hash_sha256(byte[] bytes){
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
	
	public Long secureRandomLong(){
		Long l = null;
		try {
			SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
			l = random.nextLong();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} 
		return l;
	}
	
	
	public byte[] signature_generate(byte[] bytes, PrivateKey privateKey){
		byte[] signature = null;
		Signature dsaForSign;
		try {
			dsaForSign = Signature.getInstance("SHA1withDSA");
			dsaForSign.initSign(privateKey); 
			dsaForSign.update(bytes); 
			signature = dsaForSign.sign();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			System.out.println("failed to sign data");
		}
		return signature;
	}
	
	public boolean signature_verify(byte[] signature, PublicKey publicKey, byte[] data){
		boolean verifies = false;
		Signature dsaForVerify;
		try {
			dsaForVerify = Signature.getInstance("SHA1withDSA");
			dsaForVerify.initVerify(publicKey); 
			dsaForVerify.update(data); 
			verifies = dsaForVerify.verify(signature);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			System.out.println("Signature verification failed");
		}
		return verifies;
	}
	
	
	
	public static void main(String args[]){
		Crypto c = new Crypto();
		
		String s1 = "o vasco é gay";
		System.out.println("Original Key: " + s1);
		
		byte[] hashed = c.hash_sha256(s1.getBytes());
		System.out.println("Hashed String: " + hashed);
		
		String hashed_and_encoded = c.encode_base64(hashed);
		System.out.println("Hashed and Decoded String: " + hashed_and_encoded);
		
		System.out.println("1- " + c.secureRandomLong());
		System.out.println("2- " + c.secureRandomLong());
		System.out.println("3- " + c.secureRandomLong());
		System.out.println("4- " + c.secureRandomLong());
		System.out.println("5- " + c.secureRandomLong());
		
	}
	
}










