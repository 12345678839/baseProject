package pt.unl.fct.di.adc.firstwebapp.resources;

//Adicionar check para verificar o token, isto � verificar os userRoles, creationData, expiredData, username

import java.util.logging.Logger;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;

import com.google.gson.*;
import com.google.cloud.datastore.*;

import pt.unl.fct.di.adc.firstwebapp.util.AuthToken;
import pt.unl.fct.di.adc.firstwebapp.errorObject.ErrorResponse;

@Path("/showusers")
@Produces(MediaType.APPLICATION_JSON)
public class ShowUsersResource {

	private static final String INVALID_TOKEN_CODE = "9903";
	private static final String TOKEN_EXPIRED_CODE = "9904";
	private static final String UNAUTHORIZED_CODE = "9905";

	private static final String INVALID_TOKEN = "The operation is called with an invalid token (wrong format for example)";
	private static final String TOKEN_EXPIRED = "The operation is called with a token that is expired";
	private static final String UNAUTHORIZED = "The operation is not allowed for the user role";

	private static final Logger LOG = Logger.getLogger(ShowUsersResource.class.getName());
	private static final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();

	private final Gson g = new Gson();

	public ShowUsersResource() {
	} 

	@POST
	@Path("")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response showUsers(AuthToken token) {
		
		try {
		LOG.fine("Attempt to show users");

		
		Key tokenKey = datastore.newKeyFactory().setKind("Token").newKey(token.tokenID);
		Entity tokenD = datastore.get(tokenKey);

		if ( tokenD == null || !token.checkTokenValues() || !token.username.equals(tokenD.getString("username")) ||
			    !token.role.equals(tokenD.getString("role")) ||
			    token.issuedAt != tokenD.getLong("issuedAt") ||
			    token.expiresAt != tokenD.getLong("expiresAt")) {

			    return new ErrorResponse(INVALID_TOKEN_CODE, INVALID_TOKEN).builtResponse();
			}

		long currTime = System.currentTimeMillis();

		if (currTime - token.issuedAt >= AuthToken.EXPIRATION_TIME) {
			datastore.delete(tokenKey);
			ErrorResponse response = new ErrorResponse(TOKEN_EXPIRED_CODE, TOKEN_EXPIRED);

			return response.builtResponse();
		}

		String role = tokenD.getString("role");

		if ("USER".equals(role)) {
			ErrorResponse response = new ErrorResponse(UNAUTHORIZED_CODE, UNAUTHORIZED);

			return response.builtResponse();
		}

		Query<Entity> query = Query.newEntityQueryBuilder().setKind("User").build();
		QueryResults<Entity> users = datastore.run(query);

		JsonArray arr = new JsonArray();

		while (users.hasNext()) {
			Entity u = users.next();

			JsonObject userJson = new JsonObject();
			userJson.addProperty("username", u.getKey().getName());
			userJson.addProperty("role", u.contains("role") ? u.getString("role") : "USER");

			arr.add(userJson);
		}

		JsonObject data = new JsonObject();
		data.add("users", arr);

		JsonObject response = new JsonObject();
		response.addProperty("status", "success");
		response.add("data", data);

		return Response.ok(response.toString()).build();
	}catch(Exception e) {
		 return new ErrorResponse(INVALID_TOKEN_CODE, INVALID_TOKEN).builtResponse();
	}
	}
}
