package pt.ist.sec.proj;

import java.io.Serializable;
import java.security.PublicKey;

public class SignedMessage implements Serializable{

	private String func;
	private PublicKey pubKey;
	private byte[] sign;
	private String res;
	private String nounce;
	private byte[] signNounce;
	
	//FIXME add nounce(encrip) + sign(nounce(encrip))
	public SignedMessage(String func, PublicKey pubKey, byte[] sign, String res, String nounce, byte[] signNounce) {
		this.func = func;
		this.pubKey = pubKey;
		this.sign = sign;
		this.res = res;
		this.nounce = nounce;
		this.signNounce = signNounce;
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
	
	public String getNounce() {
		return nounce;
	}
	public void setNounce(String nounce) {
		this.nounce = nounce;
	}
	
	public byte[] getSignNounce() {
		return signNounce;
	}
	public void setSignNounce(byte[] signNounce) {
		this.signNounce = signNounce;
	}
		
}
