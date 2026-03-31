package pt.unl.fct.di.adc.firstwebapp.resources;

import java.util.logging.Logger;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;
import com.google.gson.*;
import com.google.cloud.datastore.*;
import pt.unl.fct.di.adc.firstwebapp.util.AuthToken;
import pt.unl.fct.di.adc.firstwebapp.errorObject.ErrorResponse;

@Path("/showauthsessions")
@Produces(MediaType.APPLICATION_JSON)
public class ShowAuthenticatedSessionsResource {
	private static final String INVALID_TOKEN_CODE = "9903";
	private static final String TOKEN_EXPIRED_CODE = "9904";
	private static final String UNAUTHORIZED_CODE = "9905";
	private static final String FORBIDDEN_CODE = "9907";
	private static final String INVALID_TOKEN = "The operation is called with an invalid token";
	private static final String TOKEN_EXPIRED = "The operation is called with a token that is expired";
	private static final String UNAUTHORIZED = "The operation is not allowed for the user role";
	private static final String FORBIDDEN = "The operation generated a forbidden error";
	private static final Logger LOG = Logger.getLogger(ShowAuthenticatedSessionsResource.class.getName());
	private static final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
	private final Gson g = new Gson();

	@POST
	@Path("/v1")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response showSessions(AuthToken token) {
		try {
			LOG.fine("Attempt to show sessions");
			Key tokenKey = datastore.newKeyFactory().setKind("Token").newKey(token.tokenID);
			Entity tokenD = datastore.get(tokenKey);

			if (tokenD == null || token.tokenID == null || token.username == null || token.role == null) {
				return new ErrorResponse(INVALID_TOKEN_CODE, INVALID_TOKEN).builtResponse();
			}
			if (!token.tokenID.equals(tokenD.getKey().getName())
					|| !token.username.equals(tokenD.getString("username"))
					|| !token.role.equals(tokenD.getString("role"))
					|| token.issuedAt != tokenD.getLong("issuedAt")
					|| token.expiresAt != tokenD.getLong("expiresAt")) {
				return new ErrorResponse(INVALID_TOKEN_CODE, INVALID_TOKEN).builtResponse();
			}

			long currTime = System.currentTimeMillis();
			long issuedAt = tokenD.getLong("issuedAt");
			if (currTime - issuedAt >= AuthToken.EXPIRATION_TIME) {
				datastore.delete(tokenKey);
				ErrorResponse response = new ErrorResponse(TOKEN_EXPIRED_CODE, TOKEN_EXPIRED);
				return response.builtResponse();
			}

			String role = tokenD.getString("role");
			if (!"ADMIN".equals(role)) {
				ErrorResponse response = new ErrorResponse(UNAUTHORIZED_CODE, UNAUTHORIZED);
				return response.builtResponse();
			}

			Query<Entity> query = Query.newEntityQueryBuilder().setKind("Token").build();
			QueryResults<Entity> tokens = datastore.run(query);
			JsonArray sessionsArray = new JsonArray();
			while (tokens.hasNext()) {
				Entity t = tokens.next();
				long tIssuedAt = t.getLong("issuedAt");
				if (currTime - tIssuedAt < AuthToken.EXPIRATION_TIME) {
					JsonObject session = new JsonObject();
					session.addProperty("tokenId", t.getKey().getName());
					session.addProperty("username", t.contains("username") ? t.getString("username") : "");
					session.addProperty("role", t.contains("role") ? t.getString("role") : "");
					session.addProperty("expiresAt", t.contains("expiresAt") ? t.getLong("expiresAt") : 0);
					sessionsArray.add(session);
				} else {
					datastore.delete(t.getKey());
				}
			}

			JsonObject data = new JsonObject();
			data.add("sessions", sessionsArray);
			JsonObject response = new JsonObject();
			response.addProperty("status", "success");
			response.add("data", data);

			return Response.ok(g.toJson(response)).build();
		} catch (Exception e) {
			LOG.severe("Error: " + e.getMessage());
			e.printStackTrace();
			ErrorResponse response = new ErrorResponse(FORBIDDEN_CODE, FORBIDDEN);
			return response.builtResponse();
		}
	}
}
