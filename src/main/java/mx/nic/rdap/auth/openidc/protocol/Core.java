package mx.nic.rdap.auth.openidc.protocol;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;

public class Core {

	private static Logger logger = Logger.getLogger(Core.class.getName());
	
	private Core() {
		// Empty
	}
	
	public static URI getAuthenticationURI(String client, OIDCProviderMetadata providerMetadata, String redirectURI) {
		ClientID clientID = new ClientID(client);
		//URI authorizationEndpoint = URI.create("https://accounts.google.com/o/oauth2/v2/auth");
		URI authorizationEndpoint = providerMetadata.getAuthorizationEndpointURI();
		//URI authorizationEndpoint = URI.create("https://demo.c2id.com/c2id-login");
		//URI clientRedirect = URI.create("http://localhost:8080/rdap-server/domain/domain13.org");
		URI clientRedirect = URI.create(redirectURI);
		State state = new State();
		Nonce nonce = new Nonce();
		AuthenticationRequest req = new AuthenticationRequest(authorizationEndpoint,
				new ResponseType(ResponseType.Value.CODE), Scope.parse("openid email profile"), clientID,
				clientRedirect, state, nonce);
		return req.toURI();
	}
	
	public static AuthorizationCode parseAuthorizationCode(URI uri) {
		AuthenticationResponse response = null;
		try {
			response = AuthenticationResponseParser.parse(uri);
		} catch (ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
		return parseAuthorizationCode(response);
	}
	
	public static AuthorizationCode parseAuthorizationCode(AuthenticationResponse response) {
		if (response instanceof AuthenticationErrorResponse) {
			logger.log(Level.SEVERE, "ERROR response AUTH - " + ((AuthenticationErrorResponse) response).getErrorObject());
			return null;
		}
		AuthenticationSuccessResponse successResponse = (AuthenticationSuccessResponse) response;
		AuthorizationCode code = successResponse.getAuthorizationCode();
		// FIXME The state isn't remembered, find another way to valide it
		//if (!successResponse.getState().equals(state)) {
		//	logger.log(Level.SEVERE, "STATE ERROR - " + successResponse.getState() + " != " + state);
		//	return null;
		//}
		logger.log(Level.SEVERE, "RESP - " + successResponse.toString() + " - " + code);
		return code;
	}
	
	public static OIDCTokenResponse doTokenRequest(String clientID, String clientSecret, AuthorizationCode code) {
		ClientID client = new ClientID(clientID);
		Secret secret = new Secret(clientSecret);
		URI tokenEndpoint = URI.create("https://www.googleapis.com/oauth2/v4/token");
		//URI tokenEndpoint = URI.create("https://demo.c2id.com/c2id/token");
		URI clientRedirect = URI.create("http://localhost:8080/rdap-server/domain/domain13.org");
		
		ClientSecretBasic clientSecretBasic = new ClientSecretBasic(client, secret);
		AuthorizationCodeGrant authCodeGrant = new AuthorizationCodeGrant(code, clientRedirect);
		TokenRequest tokenReq = new TokenRequest(tokenEndpoint, clientSecretBasic, authCodeGrant);
		HTTPResponse httpResponse = null;
		try {
			httpResponse = tokenReq.toHTTPRequest().send();
		} catch (SerializeException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
		TokenResponse tokenResponse = null;
		try {
			tokenResponse = OIDCTokenResponseParser.parse(httpResponse);
		} catch (ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
		if (tokenResponse instanceof TokenErrorResponse) {
			logger.log(Level.SEVERE, "ERROR response TOKEN - " + ((TokenErrorResponse) tokenResponse).getErrorObject());
			return null;
		}
		OIDCTokenResponse accessTokenResponse = (OIDCTokenResponse) tokenResponse.toSuccessResponse();

		accessTokenResponse.getOIDCTokens().getIDToken();
		accessTokenResponse.getOIDCTokens().getAccessToken();
		accessTokenResponse.getOIDCTokens().getRefreshToken();
		return accessTokenResponse;
	}
	
	public static IDTokenClaimsSet verifyToken(String clientID, OIDCTokens tokens) {
		ClientID client = new ClientID(clientID);
		Issuer issuer = new Issuer("https://accounts.google.com");
		JWSAlgorithm jwsAlg = JWSAlgorithm.RS256;
		URL jwkSetURL = null;
		try {
			jwkSetURL = new URL("https://www.googleapis.com/oauth2/v3/certs/");
		} catch (MalformedURLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
		IDTokenValidator validator = new IDTokenValidator(issuer, client, jwsAlg, jwkSetURL);

		JWT idToken = tokens.getIDToken();
		IDTokenClaimsSet claims = null;
		try {
			claims = validator.validate(idToken, null);
		} catch (BadJOSEException | JOSEException e) {
			e.printStackTrace();
			return null;
		}

		logger.log(Level.SEVERE, "Logged in user " + claims.getSubject() + " - " + claims.toJSONObject().toJSONString());
		return null;
	}
	
	public static UserInfo getUserInfo(OIDCTokens tokens) {
		URI userInfoEndpoint = URI.create("https://www.googleapis.com/oauth2/v3/userinfo");
		UserInfoRequest userInfoReq = new UserInfoRequest(userInfoEndpoint, tokens.getBearerAccessToken());
		HTTPResponse httpResponse = null;
		try {
			httpResponse = userInfoReq.toHTTPRequest().send();
		} catch(IOException e) {
			e.printStackTrace();
			return null;
		}
		UserInfoResponse userInfoResponse = null;
		try {
			userInfoResponse = UserInfoResponse.parse(httpResponse);
		} catch (ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
		if (!userInfoResponse.indicatesSuccess()) {
			logger.log(Level.SEVERE, "ERR User resp - " + userInfoResponse.toErrorResponse().getErrorObject());
			return null;
		}
		
		UserInfo userInfo = userInfoResponse.toSuccessResponse().getUserInfo();
		logger.log(Level.SEVERE, "UserInfo = " + userInfo.toJSONObject().toJSONString());
		return userInfo;
	}

}
