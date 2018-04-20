package mx.nic.rdap.auth.openidc.protocol;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.client.ClientReadRequest;
import com.nimbusds.oauth2.sdk.client.ClientRegistrationErrorResponse;
import com.nimbusds.oauth2.sdk.client.ClientRegistrationResponse;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.rp.ApplicationType;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformationResponse;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientRegistrationRequest;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientRegistrationResponseParser;

import net.minidev.json.JSONObject;

public class DynamicClientRegistration {

	private static Logger logger = Logger.getLogger(DynamicClientRegistration.class.getName());
	
	private DynamicClientRegistration() {
		// Empty
	}
	
	public static OIDCClientInformation register(String clientURI, String clientAccessToken, String clientID, String clientSecret) {
		OIDCClientInformation clientInformation = null;
		if (clientID != null && !clientID.trim().isEmpty()) {
			ClientID client = new ClientID(clientID);
			Secret secret = new Secret(clientSecret);
			Map<String, String> jsonMap = new HashMap<String, String>();
			jsonMap.put("token_endpoint", "https://www.googleapis.com/oauth2/v4/token");
			JSONObject jsonObj = new JSONObject(jsonMap);
			OIDCClientMetadata clientMetadata = null;
			try {
				clientMetadata = OIDCClientMetadata.parse(jsonObj);
			} catch (ParseException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return null;
			}
			clientInformation = new OIDCClientInformation(client, null, clientMetadata, secret);
			return clientInformation;
		}
		// FIXME Check if the RP has already been registered
		// Obtenido desde
		// https://connect2id.com/products/nimbus-oauth-openid-connect-sdk/examples/openid-connect/client-registration
		
		if (clientURI != null && !clientURI.trim().isEmpty()) {
			String uri = clientURI.trim();
			String accessToken = clientAccessToken.trim();

			ClientReadRequest readRequest = new ClientReadRequest(URI.create(uri), new BearerAccessToken(accessToken));
			try {
				HTTPResponse httpResponse = readRequest.toHTTPRequest().send();
				ClientRegistrationResponse regResponse = null;
				regResponse = OIDCClientRegistrationResponseParser.parse(httpResponse);
				if (regResponse.toHTTPResponse().getStatusCode() == HTTPResponse.SC_BAD_REQUEST) {
					// We have an error
					ClientRegistrationErrorResponse errorResponse = (ClientRegistrationErrorResponse) regResponse;
					logger.log(Level.SEVERE, errorResponse.getErrorObject().getDescription());
					return null;
				}
				OIDCClientInformationResponse successResponse = (OIDCClientInformationResponse) regResponse;
				clientInformation = successResponse.getOIDCClientInformation();
			} catch (SerializeException | IOException | ParseException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				logger.log(Level.SEVERE, e.getMessage(), e);
			}
			return clientInformation;
		}
		URI clientsEndpoint = null;
		try {
			clientsEndpoint = new URI("https://demo.c2id.com/c2id/clients");
		} catch (URISyntaxException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			logger.log(Level.SEVERE, e.getMessage(), e);
			return null;
		}
		BearerAccessToken masterToken = new BearerAccessToken("ztucZS1ZyFKgh0tUEruUtiSTXhnexmd6");

		OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
		clientMetadata.setGrantTypes(Collections.singleton(GrantType.AUTHORIZATION_CODE));
		clientMetadata.setRedirectionURI(URI.create("http://localhost:8080/rdap-server/cb"));
		clientMetadata.setApplicationType(ApplicationType.NATIVE);
		clientMetadata.setName("RDAP Server RD");

		OIDCClientRegistrationRequest regRequest = new OIDCClientRegistrationRequest(clientsEndpoint, clientMetadata,
				masterToken);

		HTTPResponse httpResponse = null;
		try {
			httpResponse = regRequest.toHTTPRequest().send();
		} catch (SerializeException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			logger.log(Level.SEVERE, e.getMessage(), e);
			return null;
		}

		ClientRegistrationResponse regResponse = null;
		try {
			regResponse = OIDCClientRegistrationResponseParser.parse(httpResponse);
			if (regResponse.toHTTPResponse().getStatusCode() == HTTPResponse.SC_BAD_REQUEST) {
				// We have an error
				ClientRegistrationErrorResponse errorResponse = (ClientRegistrationErrorResponse) regResponse;
				logger.log(Level.SEVERE, errorResponse.getErrorObject().getDescription());
				return null;
			}
		} catch (ParseException | SerializeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			logger.log(Level.SEVERE, e.getMessage(), e);
			return null;
		}

		OIDCClientInformationResponse successResponse = (OIDCClientInformationResponse) regResponse;
		clientInformation = successResponse.getOIDCClientInformation();

		// The client credentials - store them:
		// The client_id
		logger.log(Level.SEVERE, "Client ID: " + clientInformation.getID());
		// The client_secret
		logger.log(Level.SEVERE, "Client secret: " + clientInformation.getSecret().getValue());
		// The client's registration resource
		logger.log(Level.SEVERE, "Client registration URI: " + clientInformation.getRegistrationURI());
		// The token for accessing the client's registration (for update, etc)
		logger.log(Level.SEVERE, "Client reg access token: " + clientInformation.getRegistrationAccessToken());

		// Print the remaining client metadata
		logger.log(Level.SEVERE, "Client metadata: " + clientInformation.getMetadata().toJSONObject());
		return clientInformation;
	}

}
