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
import pt.unl.fct.di.adc.firstwebapp.util.ModifyData;
import pt.unl.fct.di.adc.firstwebapp.errorObject.ErrorResponse;

@Path("/modaccount")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class ModifyAccountAttributesResource {

	private static final Logger LOG = Logger.getLogger(DeleteAccountResource.class.getName());
	private static final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();

	private final Gson g = new Gson();

	private static final String FORBIDDEN_CODE = "9907";
	private static final String USER_NFOUND_CODE = "9902";
	private static final String INVALID_TOKEN_CODE = "9903";
	private static final String TOKEN_EXPIRED_CODE = "9904";
	private static final String UNAUTHORIZED_CODE = "9905";
	private static final String INVALID_IN_CODE = "9906";

	private static final String USER_NOT_FOUND = "The username referred in the operation doesn't exist in registered accounts";
	private static final String INVALID_TOKEN = "The operation is called with an invalid token (wrong format for example)";
	private static final String TOKEN_EXPIRED = "The operation is called with a token that is expired";
	private static final String UNAUTHORIZED = "The operation is not allowed for the user role";
	private static final String FORBIDDEN = "The operation generated a forbidden error by other reason";
	private static final String INVALID_INPUT = "The call is using input data not following the correct specification";

	public ModifyAccountAttributesResource() {

	}

	@POST
	@Path("/v1")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response ModifyAccountAttributesResource(ModifyData mdata) {

		try {

			if (mdata == null || mdata.username == null || mdata.username.trim().isEmpty()) {

				return new ErrorResponse(FORBIDDEN_CODE, FORBIDDEN).builtResponse();
			}

			LOG.fine("Attempt to moddify user" + mdata.username);

			Key tokenKey = datastore.newKeyFactory().setKind("Token").newKey(mdata.token.tokenID);
			Entity tokenD = datastore.get(tokenKey);

			Key userKey = datastore.newKeyFactory().setKind("User").newKey(mdata.username);
			Entity user = datastore.get(userKey);

			if (user == null) {
				ErrorResponse response = new ErrorResponse(USER_NFOUND_CODE, USER_NOT_FOUND);

				return response.builtResponse();
			}

			if (tokenD == null || mdata.token.tokenID == null || mdata.token.username == null
					|| mdata.token.role == null) {
				return new ErrorResponse(INVALID_TOKEN_CODE, INVALID_TOKEN).builtResponse();
			}

			if (!mdata.token.tokenID.equals(tokenD.getKey().getName())
					|| !mdata.token.username.equals(tokenD.getString("username"))
					|| !mdata.token.role.equals(tokenD.getString("role"))
					|| mdata.token.issuedAt != tokenD.getLong("issuedAt")
					|| mdata.token.expiresAt != tokenD.getLong("expiresAt")) {

				return new ErrorResponse(INVALID_TOKEN_CODE, INVALID_TOKEN).builtResponse();
			}

			long currTime = System.currentTimeMillis();

			if (currTime - mdata.token.issuedAt >= AuthToken.EXPIRATION_TIME) {
				datastore.delete(tokenKey);

				ErrorResponse response = new ErrorResponse(TOKEN_EXPIRED_CODE, TOKEN_EXPIRED);

				return response.builtResponse();
			}

			if (mdata.token.role.equals("USER") && !mdata.token.username.equals(mdata.username)) {
				ErrorResponse response = new ErrorResponse(UNAUTHORIZED_CODE, UNAUTHORIZED);

				return response.builtResponse();
			}

			String role = tokenD.getString("role");
			String tokenUsername = tokenD.getString("username");
			String targetRole = user.getString("role");

			if (role.equals("BOFFICER")) {

				boolean isSelf = tokenUsername.equals(mdata.username);
				boolean targetIsUser = targetRole.equals("USER");

				if (!isSelf && !targetIsUser) {
					ErrorResponse response = new ErrorResponse(UNAUTHORIZED_CODE, UNAUTHORIZED);

					return response.builtResponse();
				}
			}

			if (!mdata.validRegistrationMod()) {
				ErrorResponse response = new ErrorResponse(INVALID_IN_CODE, INVALID_INPUT);

				return response.builtResponse();
			}

			Query<Entity> query = Query.newEntityQueryBuilder().setKind("Token")
					.setFilter(StructuredQuery.PropertyFilter.eq("username", mdata.username)).build();
			QueryResults<Entity> tokens = datastore.run(query);

			while (tokens.hasNext()) {
				Entity t = tokens.next();

				datastore.delete(t.getKey());
			}

			if(mdata.attributes.address.isEmpty() || mdata.attributes.address == null) {
				Entity updatedUser = Entity.newBuilder(user).set("phone", mdata.attributes.phone).build();
				datastore.put(updatedUser);
			}
			
			else if(mdata.attributes.phone.isEmpty() || mdata.attributes.phone == null) {
				Entity updatedUser = Entity.newBuilder(user).set("address", mdata.attributes.address).build();
				datastore.put(updatedUser);
			}
			else {
			Entity updatedUser = Entity.newBuilder(user).set("phone", mdata.attributes.phone)
					.set("address", mdata.attributes.address).build();
			datastore.put(updatedUser);
			}

			JsonObject status = new JsonObject();
			status.addProperty("status", "success");

			JsonObject ndata = new JsonObject();
			ndata.addProperty("message", "Updated successfully");

			status.add("data", ndata);

			return Response.ok(status.toString()).build();
		} catch (Exception e) {
			e.printStackTrace();
			LOG.severe("Error registering user: " + e.getMessage());
			return new ErrorResponse(FORBIDDEN_CODE, FORBIDDEN).builtResponse();
		}
	}
}
