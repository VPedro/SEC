package pt.ist.sec.proj;

import java.io.Serializable;
import java.security.PublicKey;

public class Message2 implements Serializable{

	private static final long serialVersionUID = 1L;
	private String func;
	private String res;
	private PublicKey key;
	
	public Message2(String func, PublicKey key, String res) {
		this.func = func;
		this.key = key;
		this.res = res;
	}
		
	public String getFunc() {
		return func;
	}
	public void setFunc(String func) {
		this.func = func;
	}
	public String getRes() {
		return res;
	}
	public void setRes(String res) {
		this.res = res;
	}
	public PublicKey getPubKey() {
		return key;
	}
	public void setPubKey(PublicKey key) {
		this.key = key;
	}	
}
