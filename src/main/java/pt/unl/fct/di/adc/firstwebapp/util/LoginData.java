//Updated login
package pt.unl.fct.di.adc.firstwebapp.util;

public class LoginData {
	
	public String username;
	public String password;
	
	public LoginData() { }
	
	public LoginData(String username, String password) {
		this.username = username;
		this.password = password;
	}
	
	private boolean nonEmptyOrBlankField(String field) {
		return field != null && !field.isBlank();
	}
	
	public boolean validUsername() {
		return nonEmptyOrBlankField(username);
	}
	
}
