package pt.unl.fct.di.adc.firstwebapp.resources;

import java.util.logging.Logger;

import org.apache.commons.codec.digest.DigestUtils;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;

import com.google.gson.*;
import com.google.cloud.datastore.*;

import java.util.Date;
import java.util.List;
import java.util.Calendar;

import pt.unl.fct.di.adc.firstwebapp.util.AuthToken;
import pt.unl.fct.di.adc.firstwebapp.util.LogoutData;
import pt.unl.fct.di.adc.firstwebapp.errorObject.ErrorResponse;

@Path("/logout")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class LogoutResource {

	private static final Logger LOG = Logger.getLogger(LogoutResource.class.getName());
	private static final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();

	private final Gson g = new Gson();

	private static final String INVALID_TOKEN_CODE = "9903";
	private static final String TOKEN_EXPIRED_CODE = "9904";
	private static final String UNAUTHORIZED_CODE = "9905";
	private static final String FORBIDDEN_CODE = "9907";

	private static final String INVALID_TOKEN = "The operation is called with an invalid token (wrong format for example)";
	private static final String TOKEN_EXPIRED = "The operation is called with a token that is expired";
	private static final String UNAUTHORIZED = "The operation is not allowed for the user role";
	private static final String FORBIDDEN = "The operation generated a forbidden error by other reason";

	public LogoutResource() {

	}

	@POST
	@Path("/v1")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response logout(LogoutData ldata) {

		try {
			
			Key userKey = datastore.newKeyFactory().setKind("User").newKey(ldata.username);
			Entity user = datastore.get(userKey);
			
			if (ldata == null || ldata.username == null || ldata.username.trim().isEmpty() || user == null) {

				return new ErrorResponse(FORBIDDEN_CODE, FORBIDDEN).builtResponse();
			}

			LOG.fine("Attempt to logout user: " + (ldata != null ? ldata.username : "null"));

			Key tokenKey = datastore.newKeyFactory().setKind("Token").newKey(ldata.token.tokenID);
			Entity tokenD = datastore.get(tokenKey);

			if (tokenD == null || ldata.token.tokenID == null || ldata.token.username == null
					|| ldata.token.role == null) {
				return new ErrorResponse(INVALID_TOKEN_CODE, INVALID_TOKEN).builtResponse();
			}

			if (!ldata.token.tokenID.equals(tokenD.getKey().getName())
					|| !ldata.token.username.equals(tokenD.getString("username"))
					|| !ldata.token.role.equals(tokenD.getString("role"))
					|| ldata.token.issuedAt != tokenD.getLong("issuedAt")
					|| ldata.token.expiresAt != tokenD.getLong("expiresAt")) {

				return new ErrorResponse(INVALID_TOKEN_CODE, INVALID_TOKEN).builtResponse();
			}

			long currTime = System.currentTimeMillis();

			if (currTime - ldata.token.issuedAt >= AuthToken.EXPIRATION_TIME) {
				datastore.delete(tokenKey);

				ErrorResponse response = new ErrorResponse(TOKEN_EXPIRED_CODE, TOKEN_EXPIRED);

				return response.builtResponse();
			}

			if ((ldata.token.role.equals("USER") || ldata.token.role.equals("BOFFICER"))
					&& !ldata.token.username.equals(ldata.username)) {
				ErrorResponse response = new ErrorResponse(UNAUTHORIZED_CODE, UNAUTHORIZED);

				return response.builtResponse();
			}

			Query<Entity> query = Query.newEntityQueryBuilder().setKind("Token")
					.setFilter(StructuredQuery.PropertyFilter.eq("username", ldata.username)).build();
			QueryResults<Entity> tokens = datastore.run(query);

			while (tokens.hasNext()) {
				Entity t = tokens.next();

				if (ldata.token.role.equals("USER") || ldata.token.role.equals("BOFFICER")) {
					if (t.getKey().getName().equals(ldata.token.tokenID)) {
						datastore.delete(t.getKey());
					}

				}

				else
					datastore.delete(t.getKey());
				
				if (t.getLong("expiresAt") < currTime) {
					datastore.delete(t.getKey());
				}
			}

			JsonObject status = new JsonObject();
			status.addProperty("status", "success");

			JsonObject data = new JsonObject();
			data.addProperty("message", "Logout successful");

			status.add("data", data);

			return Response.ok(status.toString()).build();
		} catch (Exception e) {
			e.printStackTrace();
			LOG.severe("Error registering user: " + e.getMessage());
			return new ErrorResponse(FORBIDDEN_CODE, FORBIDDEN).builtResponse();
		}
	}
}
