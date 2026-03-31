package pt.unl.fct.di.adc.firstwebapp.util;

public class ChangeRoleData{
	public String username;
	public String newRole;
	public AuthToken token;
	
	public ChangeRoleData() {
		
	}
	
	public ChangeRoleData(String username, String newRole, AuthToken token) {
		this.username = username;
		this.newRole = newRole;
		this.token = token;
	}
	
	private boolean nonEmptyOrBlankField(String field) {
		return field != null && !field.isBlank();
	}
	
	public boolean checkValidUser() {
		return nonEmptyOrBlankField(username);
	}
	
	public boolean isValidRole(String role) {
		return role.equals("ADMIN");
	}
	
	public boolean validNewRole() {
		return newRole.equals("USER") || newRole.equals("BOFFICER") || newRole.equals("ADMIN");
	}
}
