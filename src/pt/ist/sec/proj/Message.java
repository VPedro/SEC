package pt.ist.sec.proj;

import java.io.Serializable;

public class Message implements Serializable{

	private byte[] functionName;
	private byte[] domain;
	private byte[] username;
	private byte[] password;
	
	public Message(byte[] functionName, byte[] domain, byte[] username, byte[] password) {
		this.functionName = functionName;
		this.domain = domain;
		this.username = username;
		this.password = password;
	}
	public byte[] getFunctionName() {
		return functionName;
	}
	public void setFunctionName(byte[] functionName) {
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
	
}
