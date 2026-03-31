package pt.unl.fct.di.adc.firstwebapp.resources;

import java.util.logging.Logger;

import org.apache.commons.codec.digest.DigestUtils;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;

import com.google.cloud.Timestamp;
import com.google.cloud.datastore.Key;
import com.google.cloud.datastore.Entity;
import com.google.cloud.datastore.Datastore;
import com.google.cloud.datastore.KeyFactory;
import com.google.cloud.datastore.PathElement;
import com.google.cloud.datastore.DatastoreOptions;
import com.google.gson.Gson;

import pt.unl.fct.di.adc.firstwebapp.util.LoginData;
import pt.unl.fct.di.adc.firstwebapp.util.AuthToken;
import pt.unl.fct.di.adc.firstwebapp.errorObject.ErrorResponse;

@Path("/login")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class LoginResource {

	private static final String INVALID_CRED_CODE = "9900";
	private static final String USER_NFOUND_CODE = "9902";

	private static final String INVALID_CREDENTIALS = "Incorrect username or password.";
	private static final String USER_NOT_FOUND = "The username referred in the operation doesn't exist in registered accounts";
	private static final String INVALID_INPUT = "The call is using input data not following the correct specification";

	private static final String LOG_MESSAGE_LOGIN_ATTEMP = "Login attempt by user: ";
	private static final String LOG_MESSAGE_LOGIN_SUCCESSFUL = "Login successful by user: ";
	private static final String LOG_MESSAGE_WRONG_PASSWORD = "Wrong password for: ";
	private static final String LOG_MESSAGE_UNKNOW_USER = "Failed login attempt for username: ";

	private static final String USER_PWD = "user_pwd";
	private static final String USER_LOGIN_TIME = "user_login_time";

	private static final Logger LOG = Logger.getLogger(LoginResource.class.getName());
	private static final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
	private static final KeyFactory userKeyFactory = datastore.newKeyFactory().setKind("User");

	private final Gson g = new Gson();

	public LoginResource() {
	}

	@POST
	@Path("/v1")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response doLoginV1b(LoginData data) {
		
		try {
		LOG.fine(LOG_MESSAGE_LOGIN_ATTEMP + data.username);

		Key userKey = userKeyFactory.newKey(data.username);
		Entity user = datastore.get(userKey);

		if (data.validUsername() && user != null) {
			String hashedPWD = user.getString(USER_PWD);
			if (hashedPWD.equals(DigestUtils.sha512Hex(data.password))) {
				KeyFactory logKeyFactory = datastore.newKeyFactory().addAncestor(PathElement.of("User", data.username))
						.setKind("UserLog");
				Key logKey = datastore.allocateId(logKeyFactory.newKey());
				Entity userLog = Entity.newBuilder(logKey).set(USER_LOGIN_TIME, Timestamp.now()).build();
				datastore.put(userLog);

				String role = user.getString("role");
				LOG.info(LOG_MESSAGE_LOGIN_SUCCESSFUL + data.username);
				AuthToken token = new AuthToken(data.username, role);
				
				Key tokenKey = datastore.newKeyFactory().setKind("Token").newKey(token.tokenID);
				Entity tokenEntity = Entity.newBuilder(tokenKey)
				        .set("username", token.username)
				        .set("role", token.role)
				        .set("issuedAt", token.issuedAt)
				        .set("expiresAt", token.expiresAt)
				        .build();
				datastore.put(tokenEntity);

				return Response.ok(g.toJson(token)).build();
			} else {
				LOG.warning(LOG_MESSAGE_WRONG_PASSWORD + data.username);
				ErrorResponse response = new ErrorResponse(INVALID_CRED_CODE, INVALID_CREDENTIALS);
				
				return response.builtResponse();
			}
		} else {
			LOG.warning(LOG_MESSAGE_UNKNOW_USER + data.username);
			ErrorResponse response2 = new ErrorResponse(USER_NFOUND_CODE, USER_NOT_FOUND);
			
			return response2.builtResponse();
		}
	}
		catch (Exception e) {
			ErrorResponse response = new ErrorResponse(INVALID_CRED_CODE, INVALID_CREDENTIALS);
			
			return response.builtResponse();
		}
	}
}