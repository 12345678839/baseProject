package pt.unl.fct.di.adc.firstwebapp.resources;

import java.util.logging.Logger;
import org.apache.commons.codec.digest.DigestUtils;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;

import com.google.gson.*;
import com.google.cloud.datastore.*;

import pt.unl.fct.di.adc.firstwebapp.util.AuthToken;
import pt.unl.fct.di.adc.firstwebapp.util.ChangePwdData;
import pt.unl.fct.di.adc.firstwebapp.errorObject.ErrorResponse;

@Path("/changeuserpwd")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class ChangePasswordResource {
	private static final String INVALID_TOKEN_CODE = "9903";
	private static final String TOKEN_EXPIRED_CODE = "9904";
	private static final String UNAUTHORIZED_CODE = "9905";
	private static final String FORBIDDEN_CODE = "9907";
	private static final String INVALID_CRED_CODE = "9900";

	private static final String INVALID_TOKEN = "The operation is called with an invalid token (wrong format for example)";
	private static final String TOKEN_EXPIRED = "The operation is called with a token that is expired";
	private static final String UNAUTHORIZED = "The operation is not allowed for the user role";
	private static final String FORBIDDEN = "The operation generated a forbidden error by other reason";
	private static final String INVALID_CREDENTIALS = "Incorrect username or password.";

	private static final Logger LOG = Logger.getLogger(DeleteAccountResource.class.getName());
	private static final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();

	private final Gson g = new Gson();

	public ChangePasswordResource() {

	}

	@POST
	@Path("/v1")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response changePassword(ChangePwdData pdata) {

		try {

			if (pdata == null || pdata.username == null || pdata.username.trim().isEmpty() || pdata.oldPassword == null
					|| pdata.oldPassword.trim().isEmpty() || pdata.newPassword == null
							|| pdata.newPassword.trim().isEmpty()) {

				return new ErrorResponse(FORBIDDEN_CODE, FORBIDDEN).builtResponse();
			}

			LOG.fine("Attempt to change password" + pdata.username);

			Key tokenKey = datastore.newKeyFactory().setKind("Token").newKey(pdata.token.tokenID);
			Entity tokenD = datastore.get(tokenKey);

			Key userKey = datastore.newKeyFactory().setKind("User").newKey(pdata.username);
			Entity user = datastore.get(userKey);

			String hashedPWD = user.getString("user_pwd");

			if (!hashedPWD.equals(DigestUtils.sha512Hex(pdata.oldPassword))) {
				ErrorResponse response = new ErrorResponse(INVALID_CRED_CODE, INVALID_CREDENTIALS);

				return response.builtResponse();
			}

			if (tokenD == null || pdata.token.tokenID == null || pdata.token.username == null
					|| pdata.token.role == null) {
				return new ErrorResponse(INVALID_TOKEN_CODE, INVALID_TOKEN).builtResponse();
			}

			if (!pdata.token.tokenID.equals(tokenD.getKey().getName())
					|| !pdata.token.username.equals(tokenD.getString("username"))
					|| !pdata.token.role.equals(tokenD.getString("role"))
					|| pdata.token.issuedAt != tokenD.getLong("issuedAt")
					|| pdata.token.expiresAt != tokenD.getLong("expiresAt")) {

				return new ErrorResponse(INVALID_TOKEN_CODE, INVALID_TOKEN).builtResponse();
			}

			long currTime = System.currentTimeMillis();

			if (currTime - pdata.token.issuedAt >= AuthToken.EXPIRATION_TIME) {
				datastore.delete(tokenKey);

				ErrorResponse response = new ErrorResponse(TOKEN_EXPIRED_CODE, TOKEN_EXPIRED);

				return response.builtResponse();

			}

			String sameUsername = tokenD.getString("username");

			if (!sameUsername.equals(pdata.username)) {
				ErrorResponse response = new ErrorResponse(UNAUTHORIZED_CODE, UNAUTHORIZED);

				return response.builtResponse();
			}

			Query<Entity> query = Query.newEntityQueryBuilder().setKind("Token")
					.setFilter(StructuredQuery.PropertyFilter.eq("username", pdata.username)).build();

			QueryResults<Entity> tokens = datastore.run(query);

			while (tokens.hasNext()) {
				Entity t = tokens.next();

				datastore.delete(t.getKey());
			}

			Entity updatedUser = Entity.newBuilder(user).set("user_pwd", DigestUtils.sha512Hex(pdata.newPassword))
					.build();
			datastore.put(updatedUser);

			JsonObject status = new JsonObject();
			status.addProperty("status", "success");

			JsonObject ndata = new JsonObject();
			ndata.addProperty("message", "Password changed successfully");

			status.add("data", ndata);

			return Response.ok(status.toString()).build();
		} catch (Exception e) {
			e.printStackTrace();
			LOG.severe("Error registering user: " + e.getMessage());
			return new ErrorResponse(FORBIDDEN_CODE, FORBIDDEN).builtResponse();
		}

	}
}
