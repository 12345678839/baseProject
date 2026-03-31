package pt.unl.fct.di.adc.firstwebapp.util;

public class ChangePwdData{
	public String username;
	public String oldPassword;
	public String newPassword;
	public AuthToken token;
	
	public ChangePwdData() {
		
	}
	
	public ChangePwdData(String username, String oldPassword, String newPassword, AuthToken token) {
		this.username = username;
		this.oldPassword = oldPassword;
		this.newPassword = newPassword;
		this.token = token;
	}
}
