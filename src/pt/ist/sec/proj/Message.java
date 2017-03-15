package pt.ist.sec.proj;

import java.io.Serializable;
import java.security.PublicKey;

public class Message implements Serializable{

	private static final long serialVersionUID = 1L;
	private String functionName;
	private PublicKey publicKey;
	private byte[] sig_domain;
	private byte[] sig_username;
	private byte[] sig_password;
	private byte[] sig_nonce;
	private byte[] domain;
	private byte[] username;
	private byte[] password;
	private Long nonce;
	
	
	public Message(String functionName, PublicKey key, byte[] sig_domain, byte[] sig_username, byte[] sig_password, byte[] domain, byte[] username, byte[] password, Long nonce, byte[] sig_nonce) {
		this.functionName = functionName;
		this.publicKey = key;
		this.sig_domain = sig_domain;
		this.sig_username = sig_username;
		this.sig_password = sig_password;
		this.sig_nonce = sig_nonce;
		this.domain = domain;
		this.username = username;
		this.password = password;
		this.nonce = nonce;
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

	public byte[] getSig_domain() {
		return sig_domain;
	}

	public void setSig_domain(byte[] sig_domain) {
		this.sig_domain = sig_domain;
	}

	public byte[] getSig_username() {
		return sig_username;
	}

	public void setSig_username(byte[] sig_username) {
		this.sig_username = sig_username;
	}

	public byte[] getSig_password() {
		return sig_password;
	}

	public void setSig_password(byte[] sig_password) {
		this.sig_password = sig_password;
	}

	public byte[] getSig_nonce() {
		return sig_nonce;
	}

	public void setSig_nonce(byte[] sig_nonce) {
		this.sig_nonce = sig_nonce;
	}

	public Long getNonce() {
		return nonce;
	}

	public void setNonce(Long nonce) {
		this.nonce = nonce;
	}
	
}
