package pt.unl.fct.di.adc.firstwebapp.util;

public class ModifyData {

	public String username;
	public AuthToken token;
	public Attributes attributes;

	public ModifyData() {

	}

	public ModifyData(String username, Attributes attributes, AuthToken token) {
		this.username = username;
		this.token = token;
		this.attributes = attributes;
	}

	private boolean nonEmptyOrBlankField(String field) {
		return field != null && !field.isBlank();
	}

	public boolean validRegistrationMod() {
		return nonEmptyOrBlankField(attributes.phone) || nonEmptyOrBlankField(attributes.address);
	}

}
