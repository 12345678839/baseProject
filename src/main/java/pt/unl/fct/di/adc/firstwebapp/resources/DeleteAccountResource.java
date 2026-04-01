package pt.unl.fct.di.adc.firstwebapp.resources;

import java.util.logging.Logger;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;

import com.google.gson.*;
import com.google.cloud.datastore.*;

import pt.unl.fct.di.adc.firstwebapp.util.DeleteData;
import pt.unl.fct.di.adc.firstwebapp.errorObject.ErrorResponse;

@Path("/deleteaccount")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class DeleteAccountResource {

	private static final String FORBIDDEN_CODE = "9907";
	private static final String USER_NFOUND_CODE = "9902";
	private static final String INVALID_TOKEN_CODE = "9903";
	private static final String TOKEN_EXPIRED_CODE = "9904";
	private static final String UNAUTHORIZED_CODE = "9905";

	private static final String USER_NOT_FOUND = "The username referred in the operation doesn't exist in registered accounts";
	private static final String INVALID_TOKEN = "The operation is called with an invalid token (wrong format for example)";
	private static final String TOKEN_EXPIRED = "The operation is called with a token that is expired";
	private static final String UNAUTHORIZED = "The operation is not allowed for the user role";
	private static final String FORBIDDEN = "The operation generated a forbidden error by other reason";

	private static final Logger LOG = Logger.getLogger(DeleteAccountResource.class.getName());
	private static final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();

	private final Gson g = new GsonBuilder().setPrettyPrinting().create();

	@POST
	@Path("")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response deleteUser(DeleteData data) {

		try {

			if (data == null || data.username == null || data.username.trim().isEmpty()) {

				return new ErrorResponse(FORBIDDEN_CODE, FORBIDDEN).builtResponse();
			}

			LOG.info("Attempt delete user: " + data.username);

			Key userKey = datastore.newKeyFactory().setKind("User").newKey(data.username);
			Entity user = datastore.get(userKey);

			if (user == null) {
				return new ErrorResponse(USER_NFOUND_CODE, USER_NOT_FOUND).builtResponse();
			}

			Key tokenKey = datastore.newKeyFactory().setKind("Token").newKey(data.token.tokenID);
			Entity tokenD = datastore.get(tokenKey);

			if (tokenD == null) {
				return new ErrorResponse(INVALID_TOKEN_CODE, INVALID_TOKEN).builtResponse();
			}

			if (!data.token.username.equals(tokenD.getString("username"))
					|| !data.token.role.equals(tokenD.getString("role"))
					|| data.token.issuedAt != tokenD.getLong("issuedAt")
					|| data.token.expiresAt != tokenD.getLong("expiresAt")) {

				return new ErrorResponse(INVALID_TOKEN_CODE, INVALID_TOKEN).builtResponse();
			}

			long now = System.currentTimeMillis();
			if (now >= tokenD.getLong("expiresAt")) {
				datastore.delete(tokenKey);
				return new ErrorResponse(TOKEN_EXPIRED_CODE, TOKEN_EXPIRED).builtResponse();
			}

			if (!"ADMIN".equals(tokenD.getString("role"))) {
				return new ErrorResponse(UNAUTHORIZED_CODE, UNAUTHORIZED).builtResponse();
			}

			Query<Entity> query = Query.newEntityQueryBuilder().setKind("Token")
					.setFilter(StructuredQuery.PropertyFilter.eq("username", data.username)).build();

			QueryResults<Entity> results = datastore.run(query);

			while (results.hasNext()) {
				datastore.delete(results.next().getKey());
			}

			datastore.delete(userKey);

			JsonObject dataObj = new JsonObject();
			dataObj.addProperty("message", "Account deleted successfully");

			JsonObject response = new JsonObject();
			response.addProperty("status", "success");
			response.add("data", dataObj);

			return Response.ok(g.toJson(response)).build();

		} catch (Exception e) {
			e.printStackTrace();
			LOG.severe("Error: " + e.getMessage());
			return new ErrorResponse(FORBIDDEN_CODE, FORBIDDEN).builtResponse();
		}
	}
}
