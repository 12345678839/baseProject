package pt.unl.fct.di.adc.firstwebapp.errorObject;

import com.google.gson.JsonObject;
import jakarta.ws.rs.core.Response;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;


public class ErrorResponse
{

	private String code, message;

	public ErrorResponse(String code, String message) {
		this.code = code;
		this.message = message;
	}

	public Response builtResponse() {

	    JsonObject response = new JsonObject();
	    response.addProperty("status", this.code);
	    response.addProperty("data", this.message);

	    Gson gson = new Gson();

	    return Response.ok(gson.toJson(response)).build();
	}
}
