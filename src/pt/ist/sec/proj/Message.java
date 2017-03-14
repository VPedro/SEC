package pt.ist.sec.proj;

import java.io.Serializable;
import java.security.PublicKey;

public class Message implements Serializable{

	private static final long serialVersionUID = 1L;
	private String functionName;
	private PublicKey publicKey;
	private byte[] domain;
	private byte[] username;
	private byte[] password;
	
	public Message(String functionName, byte[] domain, byte[] username, byte[] password) {
		this.functionName = functionName;
		this.domain = domain;
		this.username = username;
		this.password = password;
	}
	
	public String getFunctionName() {
		return functionName;
	}
	public void setFunctionName(String functionName) {
		this.functionName = functionName;
	}
	public byte[] getDomain() {
		return domain;
	}
	public void setDomain(byte[] domain) {
		this.domain = domain;
	}
	public byte[] getUsername() {
		return username;
	}
	public void setUsername(byte[] username) {
		this.username = username;
	}
	public byte[] getPassword() {
		return password;
	}
	public void setPassword(byte[] password) {
		this.password = password;
	}
	public PublicKey getPublicKey() {
		return publicKey;
	}
	public void setPublicKey(PublicKey publicKey) {
		this.publicKey = publicKey;
	}
	
}
