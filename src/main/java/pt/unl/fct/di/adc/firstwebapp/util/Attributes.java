package pt.unl.fct.di.adc.firstwebapp.util;

public class Attributes {
		public String phone;
		public String address;

		public Attributes() {
		}

		public Attributes(String phone, String address) {
			this.phone = phone;
			this.address = address;
		}
		
		public boolean verifyAtt() {
			return this.phone != null && this.address != null;
		}
	}
