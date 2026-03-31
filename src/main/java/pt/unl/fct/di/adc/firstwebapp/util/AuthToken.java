package pt.unl.fct.di.adc.firstwebapp.util;

import java.util.UUID;

public class AuthToken {

	// Alterar o tempo de expiration
	public static final long EXPIRATION_TIME = 900000; // 15 minutos

	public String username;
	public String tokenID;
	public String role;
	public long issuedAt;
	public long expiresAt;
	

	public AuthToken() {
	}

	public AuthToken(String username, String role) {
		this.tokenID = UUID.randomUUID().toString();
		this.username = username;
		this.role = role;
		this.issuedAt = System.currentTimeMillis();
		this.expiresAt = this.issuedAt + EXPIRATION_TIME;
	}
	
	public boolean checkTokenValues() {
		return tokenID != null && username != null && role != null && issuedAt >= 0 && expiresAt >= 0;
	}
}
