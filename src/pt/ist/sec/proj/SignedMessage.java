package pt.ist.sec.proj;

import java.io.Serializable;
import java.security.PublicKey;

public class SignedMessage implements Serializable{

	private static final long serialVersionUID = 1L;
	private int id;
	private String func;
	private PublicKey pubKey;
	private byte[] sign;
	private String res;
	private byte[] value;
	private Long nonce;
	private byte[] signNonce;
	
	public SignedMessage(String func, PublicKey pubKey, byte[] sign, String res, byte[] value, Long nonce, byte[] signNonce) {
		this.func = func;
		this.pubKey = pubKey;
		this.sign = sign;
		this.res = res;
		this.value = value;
		this.nonce = nonce;
		this.signNonce = signNonce;
	}

	public void setID(int id){
		this.id = id;
	}
	public int getID(){
		return this.id;
	}
	
	public String getFunc() {
		return func;
	}
	public void setFunc(String func) {
		this.func = func;
	}
	
	public PublicKey getPubKey() {
		return pubKey;
	}
	public void setPubKey(PublicKey key) {
		this.pubKey = key;
	}
	
	public byte[] getSign() {
		return sign;
	}
	public void setSign(byte[] sign) {
		this.sign = sign;
	}
	
	public String getRes() {
		return res;
	}
	public void setRes(String res) {
		this.res = res;
	}
	
	public Long getNonce() {
		return nonce;
	}
	public void setNonce(Long nonce) {
		this.nonce = nonce;
	}
	
	public byte[] getSignNonce() {
		return signNonce;
	}
	public void setSignNonce(byte[] signNonce) {
		this.signNonce = signNonce;
	}


	public byte[] getValue() {
		return value;
	}


	public void setValue(byte[] value) {
		this.value = value;
	}
		
}
