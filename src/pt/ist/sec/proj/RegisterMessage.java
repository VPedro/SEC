package pt.ist.sec.proj;

import java.io.Serializable;
import java.security.PublicKey;

public class RegisterMessage implements Serializable{

	private String res;
	private PublicKey key;
	
	public RegisterMessage(PublicKey key, String res) {
		this.key = key;
		this.res = res;
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
