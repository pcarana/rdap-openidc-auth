package mx.nic.rdap.auth.openidc.protocol;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.Collection;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.http.HttpServletResponse;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ErrorResponse;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.SerializeException;
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
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.ClaimsRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.Prompt;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;
import com.nimbusds.openid.connect.sdk.claims.AccessTokenHash;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
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
	public static URI getAuthenticationURI(OpenIDCProvider provider, String userId, Collection<String> scopeCollection,
			String originURI) {
		ClientID clientID = new ClientID(provider.getId());
		URI authorizationEndpoint = provider.getMetadata().getAuthorizationEndpointURI();
		URI clientRedirect = URI.create(provider.getCallbackURI());
		Scope scope = Scope.parse(scopeCollection);
		ClaimsRequest claims = new ClaimsRequest();
		claims.addUserInfoClaim("purpose");
		Prompt prompt = new Prompt(Prompt.Type.LOGIN);
		// The origin URI is used as the state to remember from where the request was made
		State state = new State(Base64.encode(originURI).toString());
		Nonce nonce = new Nonce();
		AuthenticationRequest req = new AuthenticationRequest(authorizationEndpoint,
				new ResponseType(ResponseType.Value.CODE), null, scope, clientID, clientRedirect, state, nonce, null,
				prompt, -1, null, null, null, userId, null, claims, null, null, null, null);
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
			logger.log(Level.INFO, e.getMessage());
			throw new ResponseException(e.getMessage(), e);
		}
		if (!authResponse.indicatesSuccess()) {
			throw getResponseExceptionFromError(authResponse.toErrorResponse());
		}
		
		AuthenticationSuccessResponse successResponse = (AuthenticationSuccessResponse) authResponse;
		AuthorizationCode code = successResponse.getAuthorizationCode();
		if (code == null) {
			throw new ResponseException("Null authorization code");
		}
		return code;
	}
	
	/**
	 * Get the tokens response from an auth code
	 * 
	 * @param provider
	 * @param authCode
	 * @return
	 * @throws RequestException
	 * @throws ResponseException
	 */
	public static TokenResponse getTokenResponseFromAuthCode(OpenIDCProvider provider, AuthorizationCode authCode)
			throws RequestException, ResponseException {
		TokenResponse tokenResponse = getTokenResponse(provider, authCode);
		return tokenResponse;
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
			throw getResponseExceptionFromError(tokenResponse.toErrorResponse());
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
			logger.log(Level.INFO, e.getMessage());
			throw new RequestException(e.getMessage(), e);
		}
		
		try {
			return OIDCTokenResponseParser.parse(httpResponse);
		} catch (ParseException e) {
			logger.log(Level.INFO, e.getMessage());
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
	public static TokenResponse refreshToken(OpenIDCProvider provider, Collection<String> scopeCollection,
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
			logger.log(Level.INFO, e.getMessage());
			throw new RequestException(e.getMessage(), e);
		}
		
		
		if (!httpResponse.indicatesSuccess()) {
			try {
				throw new ResponseException(HTTPResponse.SC_BAD_REQUEST,
						httpResponse.getContentAsJSONObject().getAsString("error_description"));
			} catch (ParseException e) {
				logger.log(Level.INFO, e.getMessage());
				throw new RequestException(e.getMessage(), e);
			}
		}
		TokenResponse tokenResponse = null;
		try {
			tokenResponse = AccessTokenResponse.parse(httpResponse);
		} catch (ParseException e) {
			logger.log(Level.INFO, e.getMessage());
			throw new ResponseException(e.getMessage(), e);
		}

		return tokenResponse;
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
			logger.log(Level.INFO, e.getMessage());
			throw new RequestException(e.getMessage(), e);
		}

		// FIXME Set 5secs timeout
		DefaultResourceRetriever retriever = new DefaultResourceRetriever(5000, 5000);
		IDTokenValidator validator = new IDTokenValidator(issuer, client, jwsAlg, jwkSetURL, retriever);
		JWT idToken = tokens.getIDToken();
		try {
			IDTokenClaimsSet claimsSet = validator.validate(idToken, null);
			// Optional value, validate if present
			AccessTokenHash atHash = claimsSet.getAccessTokenHash();
			if (atHash != null) {
				AccessTokenHash sentHash = AccessTokenHash.compute(tokens.getAccessToken(), jwsAlg);
				if (!atHash.equals(sentHash)) {
					logger.log(Level.INFO, "Invalid access token");
					throw new ResponseException(HttpServletResponse.SC_BAD_REQUEST, "Invalid access token");
				}
			}
			// TODO Verify that the validation doesn't return Claims,
			// otherwise the UserInfo will be null (right now this wont happen since
			// the token request is made asking for the user claims)
		} catch (BadJOSEException | JOSEException e) {
			logger.log(Level.INFO, e.getMessage());
			throw new ResponseException(HttpServletResponse.SC_BAD_REQUEST, e.getMessage(), e);
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
		URI tokenEndpoint = provider.getMetadata().getRevocationEndpointURI();
		
		ClientSecretBasic clientSecretBasic = new ClientSecretBasic(client, secret);
		TokenRevocationRequest revokeReq = new TokenRevocationRequest(tokenEndpoint, clientSecretBasic, token);
		HTTPResponse httpResponse = null;
		try {
			httpResponse = revokeReq.toHTTPRequest().send();
		} catch (SerializeException | IOException e) {
			logger.log(Level.INFO, e.getMessage());
			throw new RequestException(e.getMessage(), e);
		}
		
		TokenResponse tokenResponse = null;
		try {
			tokenResponse = OIDCTokenResponseParser.parse(httpResponse);
		} catch (ParseException e) {
			logger.log(Level.INFO, e.getMessage());
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
			logger.log(Level.INFO, e.getMessage());
			throw new RequestException(e.getMessage(), e);
		}
		UserInfoResponse userInfoResponse = null;
		try {
			userInfoResponse = UserInfoResponse.parse(httpResponse);
		} catch (ParseException e) {
			logger.log(Level.INFO, e.getMessage());
			throw new ResponseException(e.getMessage(), e);
		}
		
		if (!userInfoResponse.indicatesSuccess()) {
			throw getResponseExceptionFromError(userInfoResponse.toErrorResponse());
		}
		
		UserInfoSuccessResponse userInfoSuccessResponse = userInfoResponse.toSuccessResponse();
		UserInfo userInfo = userInfoSuccessResponse.getUserInfo();
		if (userInfo == null) {
			throw new ResponseException("Null userInfo");
		}
		return userInfo;
	}
	
	/**
	 * Get a ResponseException with the proper HTTP code
	 * 
	 * @param errorResponse
	 * @return
	 */
	private static ResponseException getResponseExceptionFromError(ErrorResponse errorResponse) {
		ErrorObject errorObj = errorResponse.getErrorObject();
		String message = errorObj.getDescription();
		int code = errorObj.getHTTPStatusCode() > 0 ? errorObj.getHTTPStatusCode() : 500;
		if (errorObj.getCode() != null) {
			// Handle distinct codes based on RFC 6750 section 3.1
			switch (errorObj.getCode()) {
			case "invalid_request":
				code = 400;
				break;
			case "invalid_token":
				code = 401;
				break;
			case "insufficient_scope":
				code = 403;
				break;
			}
		}
		logger.log(Level.INFO, errorObj.toJSONObject().toJSONString());
		return new ResponseException(code, message);
	}

}
