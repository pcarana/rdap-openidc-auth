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
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.TokenRevocationRequest;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Token;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.UserInfoErrorResponse;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;

import mx.nic.rdap.auth.openidc.OpenIDCProvider;
import mx.nic.rdap.auth.openidc.exception.RequestException;
import mx.nic.rdap.auth.openidc.exception.ResponseException;
import net.minidev.json.JSONObject;

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
			int code;
			if (authResponse instanceof AuthenticationErrorResponse) {
				AuthenticationErrorResponse errorResponse = (AuthenticationErrorResponse) authResponse;
				ErrorObject errorObj = errorResponse.getErrorObject();
				message = "Response error at authorization code: HTTP Code " + errorObj.getCode() + " - " + errorObj.getDescription();
				code = errorObj.getHTTPStatusCode();
			} else {
				HTTPResponse httpResponse = authResponse.toHTTPResponse();
				message = "Response error at authorization code: HTTP Code " + httpResponse.getStatusCode() + " - " + httpResponse.getContent();
				code = httpResponse.getStatusCode();
			}
			logger.log(Level.SEVERE, message);
			throw new ResponseException(code, message);
		}
		
		AuthenticationSuccessResponse successResponse = (AuthenticationSuccessResponse) authResponse;
		AuthorizationCode code = successResponse.getAuthorizationCode();
		if (code == null) {
			throw new ResponseException("Null authorization code");
		}
		return code;
	}
	
	/**
	 * Get the tokens as a JSON Object
	 * 
	 * @param provider
	 * @param authCode
	 * @return
	 * @throws RequestException
	 * @throws ResponseException
	 */
	public static JSONObject getJSONTokensFromAuthCode(OpenIDCProvider provider, AuthorizationCode authCode)
			throws RequestException, ResponseException {
		TokenResponse tokenResponse = getTokenResponse(provider, authCode);
		if (tokenResponse.indicatesSuccess()) {
			return tokenResponse.toSuccessResponse().toJSONObject();
		}
		return tokenResponse.toErrorResponse().toJSONObject();
	}
	
	/**
	 * Get the tokens based on the authorization code sent by the OP
	 * 
	 * @param provider
	 * @param authCode
	 * @return
	 * @throws RequestException 
	 * @throws ResponseException 
	 */
	public static OIDCTokens getTokensFromAuthCode(OpenIDCProvider provider, AuthorizationCode authCode) throws RequestException, ResponseException {
		TokenResponse tokenResponse = getTokenResponse(provider, authCode);
		if (!tokenResponse.indicatesSuccess()) {
			String message = null;
			int code;
			if (tokenResponse instanceof TokenErrorResponse) {
				TokenErrorResponse errorResponse = (TokenErrorResponse) tokenResponse;
				ErrorObject errorObj = errorResponse.getErrorObject();
				message = "Response error at token response: HTTP Code " + errorObj.getCode() + " - " + errorObj.getDescription();
				code = errorObj.getHTTPStatusCode();
			} else {
				HTTPResponse httpResponse = tokenResponse.toHTTPResponse();
				message = "Response error at token response: HTTP Code " + httpResponse.getStatusCode() + " - " + httpResponse.getContent();
				code = httpResponse.getStatusCode();
			}
			logger.log(Level.SEVERE, message);
			throw new ResponseException(code, message);
		}
		OIDCTokenResponse accessTokenResponse = (OIDCTokenResponse) tokenResponse.toSuccessResponse();
		OIDCTokens tokens = accessTokenResponse.getOIDCTokens();
		if (tokens == null) {
			throw new ResponseException("Null tokens");
		}
		return tokens;
	}
	
	/**
	 * Get a TokenResponse from the OP using an authorization code
	 * 
	 * @param provider
	 * @param authCode
	 * @return
	 * @throws RequestException
	 * @throws ResponseException
	 */
	private static TokenResponse getTokenResponse(OpenIDCProvider provider, AuthorizationCode authCode) throws RequestException, ResponseException {
		ClientID client = new ClientID(provider.getId());
		Secret secret = new Secret(provider.getSecret());
		URI tokenEndpoint = provider.getMetadata().getTokenEndpointURI();
		URI clientRedirect = URI.create(provider.getCallbackURI());
		
		ClientSecretBasic clientSecretBasic = new ClientSecretBasic(client, secret);
		AuthorizationCodeGrant authCodeGrant = new AuthorizationCodeGrant(authCode, clientRedirect);
		TokenRequest tokenReq = new TokenRequest(tokenEndpoint, clientSecretBasic, authCodeGrant);
		HTTPResponse httpResponse = null;
		try {
			httpResponse = tokenReq.toHTTPRequest().send();
		} catch (SerializeException | IOException e) {
			logger.log(Level.SEVERE, e.getMessage(), e);
			throw new RequestException(e.getMessage(), e);
		}
		
		try {
			return OIDCTokenResponseParser.parse(httpResponse);
		} catch (ParseException e) {
			logger.log(Level.SEVERE, e.getMessage(), e);
			throw new ResponseException(e.getMessage(), e);
		}
	}
	
	/**
	 * Request a token refresh to the OP and return a JSON Object
	 * 
	 * @param provider
	 * @param scopeCollection
	 * @param tokens
	 * @return
	 * @throws RequestException
	 * @throws ResponseException
	 */
	public static JSONObject refreshToken(OpenIDCProvider provider, Collection<String> scopeCollection,
			RefreshToken refreshToken) throws RequestException, ResponseException {
		ClientID client = new ClientID(provider.getId());
		Secret secret = new Secret(provider.getSecret());
		URI tokenEndpoint = provider.getMetadata().getTokenEndpointURI();
		Scope scope = Scope.parse(scopeCollection);
		
		ClientSecretBasic clientSecretBasic = new ClientSecretBasic(client, secret);
		RefreshTokenGrant refreshGrant = new RefreshTokenGrant(refreshToken);
		TokenRequest tokenReq = new TokenRequest(tokenEndpoint, clientSecretBasic, refreshGrant, scope);
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
		if (tokenResponse.indicatesSuccess()) {
			return tokenResponse.toSuccessResponse().toJSONObject();
		}
		return tokenResponse.toErrorResponse().toJSONObject();
	}
	
	/**
	 * Verify the tokens at the OP. If the response has the UserInfo, then it's returned, otherwise a null value is returned.
	 * 
	 * @param provider
	 * @param tokens
	 * @return
	 * @throws RequestException 
	 */
	public static void verifyToken(OpenIDCProvider provider, OIDCTokens tokens) throws ResponseException, RequestException {
		ClientID client = new ClientID(provider.getId());
		Issuer issuer = provider.getMetadata().getIssuer();
		// Use recommended algorithm
		JWSAlgorithm jwsAlg = JWSAlgorithm.RS256;
		URL jwkSetURL = null;
		try {
			jwkSetURL = provider.getMetadata().getJWKSetURI().toURL();
		} catch (MalformedURLException e) {
			logger.log(Level.SEVERE, e.getMessage(), e);
			throw new RequestException(e.getMessage(), e);
		}

		IDTokenValidator validator = new IDTokenValidator(issuer, client, jwsAlg, jwkSetURL);
		JWT idToken = tokens.getIDToken();
		try {
			validator.validate(idToken, null);
			// TODO Verify that the validation doesn't return Claims,
			// otherwise the UserInfo will be null
		} catch (BadJOSEException e) {
			logger.log(Level.SEVERE, e.getMessage(), e);
			throw new ResponseException(e.getMessage(), e);
		} catch (JOSEException e) {
			logger.log(Level.SEVERE, e.getMessage(), e);
			throw new RequestException(e.getMessage(), e);
		}
	}
	
	/**
	 * Request a token revocation to the OP and return the response as a JSON Object
	 * 
	 * @param provider
	 * @param token
	 * @return
	 * @throws RequestException
	 * @throws ResponseException
	 */
	public static JSONObject revokeToken(OpenIDCProvider provider, Token token) throws RequestException, ResponseException {
		ClientID client = new ClientID(provider.getId());
		Secret secret = new Secret(provider.getSecret());
		URI tokenEndpoint = provider.getMetadata().getTokenEndpointURI();
		
		ClientSecretBasic clientSecretBasic = new ClientSecretBasic(client, secret);
		TokenRevocationRequest revokeReq = new TokenRevocationRequest(tokenEndpoint, clientSecretBasic, token);
		HTTPResponse httpResponse = null;
		try {
			httpResponse = revokeReq.toHTTPRequest().send();
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
		if (tokenResponse.indicatesSuccess()) {
			return tokenResponse.toSuccessResponse().toJSONObject();
		}
		return tokenResponse.toErrorResponse().toJSONObject();
	}
	
	/**
	 * Get the UserInfo using the specified tokens
	 * 
	 * @param provider
	 * @param tokens
	 * @return
	 */
	public static UserInfo getUserInfo(OpenIDCProvider provider, OIDCTokens tokens) throws RequestException, ResponseException {
		URI userInfoEndpoint = provider.getMetadata().getUserInfoEndpointURI();
		UserInfoRequest userInfoReq = new UserInfoRequest(userInfoEndpoint, tokens.getBearerAccessToken());
		HTTPResponse httpResponse = null;
		try {
			httpResponse = userInfoReq.toHTTPRequest().send();
		} catch (IOException e) {
			logger.log(Level.SEVERE, e.getMessage(), e);
			throw new RequestException(e.getMessage(), e);
		}
		UserInfoResponse userInfoResponse = null;
		try {
			userInfoResponse = UserInfoResponse.parse(httpResponse);
		} catch (ParseException e) {
			logger.log(Level.SEVERE, e.getMessage(), e);
			throw new ResponseException(e.getMessage(), e);
		}
		
		if (!userInfoResponse.indicatesSuccess()) {
			String message = null;
			int code;
			if (userInfoResponse instanceof UserInfoErrorResponse) {
				UserInfoErrorResponse errorResponse = (UserInfoErrorResponse) userInfoResponse;
				ErrorObject errorObj = errorResponse.getErrorObject();
				message = "Response error at userInfo response: HTTP Code " + errorObj.getCode() + " - " + errorObj.getDescription();
				code = errorObj.getHTTPStatusCode();
			} else {
				message = "Response error at userInfo response: HTTP Code " + httpResponse.getStatusCode() + " - " + httpResponse.getContent();
				code = httpResponse.getStatusCode();
			}
			logger.log(Level.SEVERE, message);
			throw new ResponseException(code, message);
		}
		
		UserInfoSuccessResponse userInfoSuccessResponse = userInfoResponse.toSuccessResponse();
		UserInfo userInfo = userInfoSuccessResponse.getUserInfo();
		if (userInfo == null) {
			throw new ResponseException("Null userInfo");
		}
		return userInfo;
	}

}
