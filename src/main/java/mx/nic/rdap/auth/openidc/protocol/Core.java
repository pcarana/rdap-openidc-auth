package mx.nic.rdap.auth.openidc.protocol;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.Collection;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
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
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;

import mx.nic.rdap.auth.openidc.OpenIDCProvider;
import mx.nic.rdap.auth.openidc.exception.RequestException;
import mx.nic.rdap.auth.openidc.exception.ResponseException;

public class Core {

	private static Logger logger = Logger.getLogger(Core.class.getName());
	
	private Core() {
		// Empty
	}
	
	/**
	 * Assemble and return the URI where the end user will provide its credentials.
	 * Authorization Code Flow used by default.
	 * 
	 * @param provider
	 * @param scopeCollection
	 * @param originURI
	 * @return
	 */
	public static URI getAuthenticationURI(OpenIDCProvider provider, Collection<String> scopeCollection,
			String originURI) {
		ClientID clientID = new ClientID(provider.getId());
		URI authorizationEndpoint = provider.getMetadata().getAuthorizationEndpointURI();
		URI clientRedirect = URI.create(provider.getCallbackURI());
		Scope scope = Scope.parse(scopeCollection);
		// The origin URI is used as the state to remember from where the request was
		// made
		State state = new State(Base64.encode(originURI).toString());
		Nonce nonce = new Nonce();
		AuthenticationRequest req = new AuthenticationRequest(authorizationEndpoint,
				new ResponseType(ResponseType.Value.CODE), scope, clientID, clientRedirect, state, nonce);
		return req.toURI();
	}
	
	/**
	 * Return the Authorization code based on the query parameters of the request sent by the OP
	 * 
	 * @param requestQuery
	 * @return
	 */
	public static AuthorizationCode parseAuthorizationCode(String requestQuery) throws ResponseException {
		AuthenticationResponse authResponse = null;
		try {
			// Use a relative URI
			authResponse = AuthenticationResponseParser.parse(URI.create("https:///?".concat(requestQuery)));
		} catch (ParseException e) {
			logger.log(Level.SEVERE, e.getMessage(), e);
			throw new ResponseException(e.getMessage(), e);
		}
		if (!authResponse.indicatesSuccess()) {
			String message = null;
			if (authResponse instanceof AuthenticationErrorResponse) {
				AuthenticationErrorResponse errorResponse = (AuthenticationErrorResponse) authResponse;
				ErrorObject errorObj = errorResponse.getErrorObject();
				message = "Response error at authorization code: HTTP Code " + errorObj.getCode() + " - " + errorObj.getDescription();
			} else {
				HTTPResponse httpResponse = authResponse.toHTTPResponse();
				message = "Response error at authorization code: HTTP Code " + httpResponse.getStatusCode() + " - " + httpResponse.getContent();
			}
			logger.log(Level.SEVERE, message);
			throw new ResponseException(message);
		}
		
		AuthenticationSuccessResponse successResponse = (AuthenticationSuccessResponse) authResponse;
		AuthorizationCode code = successResponse.getAuthorizationCode();
		if (code == null) {
			throw new ResponseException("Null authorization code");
		}
		return code;
	}
	
	/**
	 * Get the tokens based on the authorization code sent by the OP
	 * 
	 * @param provider
	 * @param code
	 * @return
	 * @throws RequestException 
	 * @throws ResponseException 
	 */
	public static OIDCTokens getTokensFromAuthCode(OpenIDCProvider provider, AuthorizationCode code) throws RequestException, ResponseException {
		ClientID client = new ClientID(provider.getId());
		Secret secret = new Secret(provider.getSecret());
		URI tokenEndpoint = provider.getMetadata().getTokenEndpointURI();
		URI clientRedirect = URI.create(provider.getCallbackURI());
		
		ClientSecretBasic clientSecretBasic = new ClientSecretBasic(client, secret);
		AuthorizationCodeGrant authCodeGrant = new AuthorizationCodeGrant(code, clientRedirect);
		TokenRequest tokenReq = new TokenRequest(tokenEndpoint, clientSecretBasic, authCodeGrant);
		HTTPResponse httpResponse = null;
		try {
			httpResponse = tokenReq.toHTTPRequest().send();
		} catch (SerializeException | IOException e) {
			logger.log(Level.SEVERE, e.getMessage(), e);
			throw new RequestException(e.getMessage(), e);
		}
		
		TokenResponse tokenResponse = null;
		try {
			tokenResponse = OIDCTokenResponseParser.parse(httpResponse);
		} catch (ParseException e) {
			logger.log(Level.SEVERE, e.getMessage(), e);
			throw new ResponseException(e.getMessage(), e);
		}
		if (!tokenResponse.indicatesSuccess()) {
			String message = null;
			if (tokenResponse instanceof TokenErrorResponse) {
				TokenErrorResponse errorResponse = (TokenErrorResponse) tokenResponse;
				ErrorObject errorObj = errorResponse.getErrorObject();
				message = "Response error at token response: HTTP Code " + errorObj.getCode() + " - " + errorObj.getDescription();
			} else {
				message = "Response error at token response: HTTP Code " + httpResponse.getStatusCode() + " - " + httpResponse.getContent();
			}
			logger.log(Level.SEVERE, message);
			throw new ResponseException(message);
		}
		OIDCTokenResponse accessTokenResponse = (OIDCTokenResponse) tokenResponse.toSuccessResponse();
		OIDCTokens tokens = accessTokenResponse.getOIDCTokens();
		if (tokens == null) {
			throw new ResponseException("Null tokens");
		}
		return tokens;
	}
	
	public static IDTokenClaimsSet verifyToken(OpenIDCProvider provider, OIDCTokens tokens) {
		ClientID client = new ClientID(provider.getId());
		Issuer issuer = provider.getMetadata().getIssuer();
		JWSAlgorithm jwsAlg = JWSAlgorithm.RS256;
		URL jwkSetURL = null;
		try {
			jwkSetURL = provider.getMetadata().getJWKSetURI().toURL();
		} catch (MalformedURLException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
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
		return claims;
	}
	
	public static UserInfo getUserInfo(OpenIDCProvider provider, OIDCTokens tokens) {
		URI userInfoEndpoint = provider.getMetadata().getUserInfoEndpointURI();
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
