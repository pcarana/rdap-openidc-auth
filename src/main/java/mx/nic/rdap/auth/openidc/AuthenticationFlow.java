package mx.nic.rdap.auth.openidc;

import java.net.URI;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Token;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;

import mx.nic.rdap.auth.openidc.exception.RequestException;
import mx.nic.rdap.auth.openidc.exception.ResponseException;
import mx.nic.rdap.auth.openidc.protocol.Core;
import mx.nic.rdap.auth.openidc.protocol.Discovery;
import mx.nic.rdap.auth.openidc.shiro.IdentifierFilter;
import net.minidev.json.JSONObject;

public class AuthenticationFlow {

	/**
	 * ID used to get the "purpose" claims
	 */
	private static final String PURPOSE_CLAIM = "purpose";
	
	public static Logger logger = Logger.getLogger(AuthenticationFlow.class.getName());

	private AuthenticationFlow() {
		// Empty
	}

	/**
	 * Updates an OP provider metadata if it doesn't have any metadata already loaded
	 * 
	 * @param userId
	 * @param provider
	 * @throws RequestException
	 * @throws ResponseException
	 */
	public static void updateProviderMetadata(String userId, OpenIDCProvider provider)
			throws RequestException, ResponseException {
		String providerURI = Discovery.discoverProvider(userId);
		if (provider.getMetadata() == null) {
			OIDCProviderMetadata metadata = Discovery.getProviderMetadata(providerURI);
			provider.setMetadata(metadata);
		}
		// TODO Handle multiple providers
	}
	
	/**
	 * Return the location used to redirect the user in order to perform the OP authentication
	 * 
	 * @param request
	 * @param provider
	 * @return
	 */
	public static String getAuthenticationLocation(String userId, ServletRequest request, OpenIDCProvider provider) {
		String originUri = getOriginURI(request);
		// Required "openid" scope, "purpose" should be supported
		Set<String> scopes = getRequestScopes(provider);
		URI location = Core.getAuthenticationURI(provider, userId, scopes, originUri);
		return location.toString();
	}

	/**
	 * Return the UserInfo using the OP's authorization code
	 * 
	 * @param requestQuery
	 * @param provider
	 * @return
	 * @throws RequestException
	 * @throws ResponseException
	 */
	public static UserInfo getUserInfoFromAuthCode(String requestQuery, OpenIDCProvider provider) throws RequestException, ResponseException {
		AuthorizationCode authCode = Core.parseAuthorizationCode(requestQuery);
		OIDCTokens tokens = Core.getTokensFromAuthCode(provider, authCode);
		return getUserInfoFromToken(tokens, provider);
	}
	
	/**
	 * Get the UserInfo based on the tokens (these are validated first at the OP)
	 * 
	 * @param tokens
	 * @return
	 * @throws Exception
	 */
	public static UserInfo getUserInfoFromToken(OIDCTokens tokens, OpenIDCProvider provider) throws RequestException, ResponseException {
		Core.verifyToken(provider, tokens);
		return Core.getUserInfo(provider, tokens);
	}
	
	/**
	 * Return the token as a JSON Object, based on the authorization code sent by the OP
	 * 
	 * @param requestQuery
	 * @param provider
	 * @return
	 * @throws RequestException
	 * @throws ResponseException
	 */
	public static JSONObject getTokenJSON(String requestQuery, OpenIDCProvider provider) throws RequestException, ResponseException {
		AuthorizationCode authCode = Core.parseAuthorizationCode(requestQuery);
		return Core.getJSONTokensFromAuthCode(provider, authCode);
	}
	
	/**
	 * Get a token refresh response as a JSON Object
	 * 
	 * @param refreshToken
	 * @param provider
	 * @return
	 * @throws RequestException
	 * @throws ResponseException
	 */
	public static JSONObject getTokenRefreshJSON(String refreshToken, OpenIDCProvider provider) throws RequestException, ResponseException {
		RefreshToken refreshTokenObj = new RefreshToken(refreshToken);
		Set<String> scopes = getRequestScopes(provider);
		return Core.refreshToken(provider, scopes, refreshTokenObj);
	}
	
	/**
	 * Get a token revoke response as a JSON Object
	 * 
	 * @param token
	 * @param provider
	 * @return
	 * @throws RequestException
	 * @throws ResponseException
	 */
	public static JSONObject getTokenRevokeJSON(String token, OpenIDCProvider provider) throws RequestException, ResponseException {
		Token tokenObject = new Token(token) {
			
			private static final long serialVersionUID = 1L;

			@Override
			public JSONObject toJSONObject() {
				JSONObject o = new JSONObject();
				o.put("token", getValue());
				return o;
			}
			
			@Override
			public Set<String> getParameterNames() {
				Set<String> paramNames = new HashSet<>();
				paramNames.add("token");
				return paramNames;
			}
		};
		return Core.revokeToken(provider, tokenObject);
	}
	
	/**
	 * Get the RDAP "purpose" claims as user roles
	 * 
	 * @param userInfo
	 * @return
	 */
	public static Set<String> getPurposeAsRoles(UserInfo userInfo) {
		Set<String> roles = new HashSet<String>();
		if (userInfo.getClaim(PURPOSE_CLAIM) != null) {
			// Use them as lowercase
			roles.add(userInfo.getStringClaim(PURPOSE_CLAIM).toLowerCase());
		}
		return roles;
	}

	/**
	 * Returns the original URI from a ServletRequest
	 * 
	 * @param request
	 * @return
	 */
	private static String getOriginURI(ServletRequest request) {
		StringBuffer sb = new StringBuffer();
		if (request instanceof HttpServletRequest) {
			HttpServletRequest httpRequest = (HttpServletRequest) request;
			String requestURI = httpRequest.getRequestURI();
			String contextPath = httpRequest.getContextPath();
			if (!contextPath.isEmpty()) {
				sb.append(requestURI.substring(contextPath.length()));
			} else {
				sb.append(requestURI);
			}
			if (httpRequest.getQueryString() != null) {
				// Remove the "id" parameter
				Map<String, String[]> cleanMap = new HashMap<String, String[]>();
				for (String key : httpRequest.getParameterMap().keySet()) {
					if (!key.equals(IdentifierFilter.ID_PARAM)) {
						cleanMap.put(key, httpRequest.getParameterMap().get(key));
					}
				}
				sb.append("?");
				cleanMap.forEach((k, v) -> {
					for (String value : v) {
						sb.append(k);
						sb.append("=");
						sb.append(value);
						sb.append("&");
					}
				});
				sb.deleteCharAt(sb.length() - 1);
			}
		} else {
			// TODO Build it (how?)
			// ServletRequest request = userToken.getRequest();
			// sb.append(request.getScheme());
			// sb.append("://");
			// sb.append(request.getServerName());
			// if (request.getServerPort() > 0) {
			// sb.append(request.getServerPort());
			// }
			// if (request.getServletContext().getContextPath().isEmpty()) {
			//	sb.append("/");
			// } else {
			//	sb.append(request.getServletContext().getContextPath());
			//}
			// // Apparently the path is not available
			// sb.append();
		}
		return sb.toString();
	}
	
	/**
	 * Get the set of scopes that the RP will request to the OP
	 * 
	 * @param provider
	 * @return
	 */
	private static Set<String> getRequestScopes(OpenIDCProvider provider) {
		Set<String> scopes = new HashSet<String>();
		scopes.add("openid");
		scopes.add("profile");
		return scopes;
	}
}
