package pt.unl.fct.di.adc.firstwebapp.util;

public class DeleteData {
	
	public String username;
	public AuthToken token;
	
	public DeleteData() { }
	
	public DeleteData(String username, AuthToken token) {
		this.username = username;
		this.token = token;
	}
	
}
