package pt.unl.fct.di.adc.firstwebapp.resources;

import java.util.logging.Logger;
import org.apache.commons.codec.digest.DigestUtils;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;

import com.google.gson.*;
import com.google.cloud.datastore.*;

import pt.unl.fct.di.adc.firstwebapp.util.AuthToken;
import pt.unl.fct.di.adc.firstwebapp.util.ShowUserData;
import pt.unl.fct.di.adc.firstwebapp.errorObject.ErrorResponse;

@Path("/showuserrole")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class ShowUserRoleResource {

	private static final String INVALID_TOKEN_CODE = "9903";
	private static final String TOKEN_EXPIRED_CODE = "9904";
	private static final String UNAUTHORIZED_CODE = "9905";
	private static final String FORBIDDEN_CODE = "9907";
	private static final String USER_NOT_CODE = "9902";

	private static final String INVALID_TOKEN = "The operation is called with an invalid token (wrong format for example)";
	private static final String TOKEN_EXPIRED = "The operation is called with a token that is expired";
	private static final String UNAUTHORIZED = "The operation is not allowed for the user role";
	private static final String FORBIDDEN = "The operation generated a forbidden error by other reason";
	private static final String USER_NOT_FOUND = "The username referred in the operation doesn't exist in registered accounts";

	private static final Logger LOG = Logger.getLogger(DeleteAccountResource.class.getName());
	private static final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();

	private final Gson g = new Gson();

	public ShowUserRoleResource() {

	}

	@POST
	@Path("")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response showUserRole(ShowUserData sudata) {

		try {

			
			if (sudata == null || sudata.username == null || sudata.username.trim().isEmpty() || sudata.token == null
					|| sudata.token.tokenID == null || sudata.token.username == null || sudata.token.role == null) {

				return new ErrorResponse(FORBIDDEN_CODE, FORBIDDEN).builtResponse();
			}

			LOG.fine("Attempt to show user role: " + sudata.username);

			Key tokenKey = datastore.newKeyFactory().setKind("Token").newKey(sudata.token.tokenID);
			Entity tokenD = datastore.get(tokenKey);

			Key userKey = datastore.newKeyFactory().setKind("User").newKey(sudata.username);
			Entity user = datastore.get(userKey);

			if (user == null || !sudata.checkValidUser()) {
				return new ErrorResponse(USER_NOT_CODE, USER_NOT_FOUND).builtResponse();
			}

			if (tokenD == null) {
				return new ErrorResponse(INVALID_TOKEN_CODE, INVALID_TOKEN).builtResponse();
			}

			
			if (!sudata.token.tokenID.equals(tokenD.getKey().getName())
					|| !sudata.token.username.equals(tokenD.getString("username"))
					|| !sudata.token.role.equals(tokenD.getString("role"))
					|| sudata.token.issuedAt != tokenD.getLong("issuedAt")
					|| sudata.token.expiresAt != tokenD.getLong("expiresAt")) {

				return new ErrorResponse(INVALID_TOKEN_CODE, INVALID_TOKEN).builtResponse();
			}

			long currTime = System.currentTimeMillis();

			
			if (currTime >= sudata.token.expiresAt) {
				datastore.delete(tokenKey);
				return new ErrorResponse(TOKEN_EXPIRED_CODE, TOKEN_EXPIRED).builtResponse();
			}

			String tokenRole = tokenD.getString("role");

			if (!sudata.isValidRole(tokenRole)) {
				return new ErrorResponse(UNAUTHORIZED_CODE, UNAUTHORIZED).builtResponse();
			}

			JsonObject userJson = new JsonObject();
			userJson.addProperty("username", user.getKey().getName());
			userJson.addProperty("role", user.contains("role") ? user.getString("role") : "USER");

			JsonObject status = new JsonObject();
			status.addProperty("status", "success");
			status.add("data", userJson);

			return Response.ok(status.toString()).build();

		} catch (Exception e) {
			e.printStackTrace();
			LOG.severe("Error: " + e.getMessage());
			return new ErrorResponse(FORBIDDEN_CODE, FORBIDDEN).builtResponse();
		}
	}
}
