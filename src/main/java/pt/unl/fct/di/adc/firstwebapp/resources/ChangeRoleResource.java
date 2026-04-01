//FALTA O FORBIDDEN
package pt.unl.fct.di.adc.firstwebapp.resources;

import java.util.logging.Logger;
import org.apache.commons.codec.digest.DigestUtils;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;

import com.google.gson.*;
import com.google.cloud.datastore.*;

import pt.unl.fct.di.adc.firstwebapp.util.AuthToken;
import pt.unl.fct.di.adc.firstwebapp.util.ChangeRoleData;
import pt.unl.fct.di.adc.firstwebapp.errorObject.ErrorResponse;

@Path("/changeuserrole")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class ChangeRoleResource {

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

	public ChangeRoleResource() {

	}

	@POST
	@Path("")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response changeRole(ChangeRoleData rdata) {

		if (rdata == null || rdata.username == null || rdata.username.trim().isEmpty() || !rdata.validNewRole()) {

			return new ErrorResponse(FORBIDDEN_CODE, FORBIDDEN).builtResponse();
		}

		try {
			LOG.fine("Attempt to change role" + rdata.username);

			Key tokenKey = datastore.newKeyFactory().setKind("Token").newKey(rdata.token.tokenID);
			Entity tokenD = datastore.get(tokenKey);

			Key userKey = datastore.newKeyFactory().setKind("User").newKey(rdata.username);
			Entity user = datastore.get(userKey);

			if (user == null || !rdata.checkValidUser()) {
				ErrorResponse response = new ErrorResponse(USER_NOT_CODE, USER_NOT_FOUND);

				return response.builtResponse();
			}

			if (tokenD == null || rdata.token.tokenID == null || rdata.token.username == null
					|| rdata.token.role == null) {
				return new ErrorResponse(INVALID_TOKEN_CODE, INVALID_TOKEN).builtResponse();
			}

			if (!rdata.token.tokenID.equals(tokenD.getKey().getName())
					|| !rdata.token.username.equals(tokenD.getString("username"))
					|| !rdata.token.role.equals(tokenD.getString("role"))
					|| rdata.token.issuedAt != tokenD.getLong("issuedAt")
					|| rdata.token.expiresAt != tokenD.getLong("expiresAt")) {

				return new ErrorResponse(INVALID_TOKEN_CODE, INVALID_TOKEN).builtResponse();
			}

			long currTime = System.currentTimeMillis();

			if (currTime - rdata.token.issuedAt >= AuthToken.EXPIRATION_TIME) {
				datastore.delete(tokenKey);

				ErrorResponse response = new ErrorResponse(TOKEN_EXPIRED_CODE, TOKEN_EXPIRED);

				return response.builtResponse();

			}

			String roleType = tokenD.getString("role");

			if (!rdata.isValidRole(roleType)) {
				ErrorResponse response = new ErrorResponse(UNAUTHORIZED_CODE, UNAUTHORIZED);

				return response.builtResponse();
			}

			Query<Entity> query = Query.newEntityQueryBuilder().setKind("Token")
					.setFilter(StructuredQuery.PropertyFilter.eq("username", rdata.username)).build();

			QueryResults<Entity> tokens = datastore.run(query);

			//Se o role for igual devia manter os tokens
			while (tokens.hasNext()) {
				Entity t = tokens.next();

				datastore.delete(t.getKey());
			}

			Entity updatedUser = Entity.newBuilder(user).set("role", rdata.newRole).build();
			datastore.put(updatedUser);

			JsonObject status = new JsonObject();
			status.addProperty("status", "success");

			JsonObject ndata = new JsonObject();
			ndata.addProperty("message", "Role updated successfully");

			status.add("data", ndata);

			return Response.ok(status.toString()).build();
		} catch (

		Exception e) {
			e.printStackTrace();
			LOG.severe("Error registering user: " + e.getMessage());
			return new ErrorResponse(FORBIDDEN_CODE, FORBIDDEN).builtResponse();
		}
	}
}
