package pt.unl.fct.di.adc.firstwebapp.resources;

import java.util.logging.Logger;

import org.apache.commons.codec.digest.DigestUtils;

import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;


import com.google.cloud.Timestamp;
import com.google.cloud.datastore.Key;
import com.google.cloud.datastore.Entity;
import com.google.cloud.datastore.Datastore;
import com.google.cloud.datastore.Transaction;
import com.google.cloud.datastore.DatastoreOptions;

import pt.unl.fct.di.adc.firstwebapp.util.RegisterData;
import pt.unl.fct.di.adc.firstwebapp.errorObject.ErrorResponse;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;

@Path("/createaccount")
public class RegisterResource {

	public static final String INVAL_CODE = "9906";
	public static final String USER_EXISTS_CODE = "9901";

	public static final String USER_ALREADY_EXISTS = "Error in creating an account because the username already exists";
	public static final String INVALID_INPUT = "The call is using input data not following the correct specification";

	private static final Logger LOG = Logger.getLogger(RegisterResource.class.getName());
	private static final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();

	private final Gson g = new Gson();
	public RegisterResource() {
	}

	@POST
	@Path("")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response registerUserV3(RegisterData data) {
		LOG.fine("Attempt to register user: " + data.username);

		if (!data.validRegistration()) {
			ErrorResponse response = new ErrorResponse(INVAL_CODE, INVALID_INPUT);

			return response.builtResponse();
		}
		
		try {
			Transaction txn = datastore.newTransaction();
			Key userKey = datastore.newKeyFactory().setKind("User").newKey(data.username);
			Entity user = txn.get(userKey);

			if (user != null) {
				txn.rollback();

				ErrorResponse response = new ErrorResponse(USER_EXISTS_CODE, USER_ALREADY_EXISTS);

				return response.builtResponse();

			} else {
				user = Entity.newBuilder(userKey).set("username", data.username).set("role", data.role)
						.set("user_pwd", DigestUtils.sha512Hex(data.password)).set("phone", data.phone)
						.set("address", data.address).set("creation_time", Timestamp.now()).build();
				txn.put(user);
				txn.commit();
				LOG.info("User registered " + data.username);
				
				JsonObject dataR = new JsonObject();
				dataR.addProperty("username", data.username);
				dataR.addProperty("role", data.role);
				
				
				JsonObject response = new JsonObject();
				response.addProperty("status", "success");
				response.add("data", dataR);

				return Response.ok(g.toJson(response)).build();
			}
		} catch (Exception e) {
			e.printStackTrace();
			LOG.severe("Error registering user: " + e.getMessage());
			return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Error registering user.").build();
		}
	}
}
