package pt.unl.fct.di.adc.firstwebapp.util;

public class ShowUserData{
	public String username;
	public AuthToken token;
	
	public ShowUserData() {
		
	}
	
	public ShowUserData(String username, AuthToken token) {
		this.username = username;
		this.token = token;
	}
	
	private boolean nonEmptyOrBlankField(String field) {
		return field != null && !field.isBlank();
	}
	
	public boolean checkValidUser() {
		return nonEmptyOrBlankField(username);
	}
	
	public boolean isValidRole(String role) {
		return role.equals("ADMIN") || role.equals("BOFFICER");
	}
}
