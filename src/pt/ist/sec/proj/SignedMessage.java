package pt.ist.sec.proj;

import java.io.Serializable;
import java.security.PublicKey;

public class SignedMessage implements Serializable{

	private String func;
	private PublicKey pubKey;
	private byte[] sign;
	private String res;
	
	public SignedMessage(String func, PublicKey pubKey, byte[] sign, String res) {
		this.func = func;
		this.pubKey = pubKey;
		this.sign = sign;
		this.res = res;
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

}
