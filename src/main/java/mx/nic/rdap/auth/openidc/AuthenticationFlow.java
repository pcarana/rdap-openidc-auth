package mx.nic.rdap.auth.openidc;

import java.net.URI;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;

import mx.nic.rdap.auth.openidc.protocol.Core;
import mx.nic.rdap.auth.openidc.protocol.Discovery;
import mx.nic.rdap.auth.openidc.shiro.IdentifierFilter;

public class AuthenticationFlow {

	private static final String PURPOSE_CLAIM = "purpose";
	
	public static Logger logger = Logger.getLogger(AuthenticationFlow.class.getName());

	private AuthenticationFlow() {
		// Empty
	}

	public static void updateProviderMetadata(String userId, OpenIDCProvider provider) {
		String providerURI = Discovery.discoverProvider(userId);
		if (provider.getMetadata() == null) {
			OIDCProviderMetadata metadata = Discovery.getProviderMetadata(providerURI);
			provider.setMetadata(metadata);
		}
		// TODO Handle multiple providers
//		OpenIDCProvider provider = Configuration.getProvidersMap().get(providerURI);
//		if (provider == null) {
//			OIDCProviderMetadata metadata = Discovery.getProviderMetadata(providerURI);
//			Configuration.addProvider(providerURI, clientId, clientSecret, clientCallbackURI, metadata);
//		}
	}
	
	public static String getAuthenticationLocation(ServletRequest request, OpenIDCProvider provider) {
		String originUri = getOriginURI(request);
		Set<String> scope = new HashSet<String>();
		scope.add("openid");
		scope.add("email");
		if (provider.getMetadata().getScopes().contains(PURPOSE_CLAIM)) {
			scope.add(PURPOSE_CLAIM);
		}
		URI location = Core.getAuthenticationURI(provider, scope, originUri);
		logger.log(Level.SEVERE, "Before redirect to " + location.toString());
		return location.toString();
	}

	public static UserInfo validateAuthCode(String requestQuery) throws Exception {
		OIDCTokens tokens = null;
		logger.log(Level.SEVERE, "At AuthResponseToken");
		AuthenticationResponse authResponse = null;
		try {
			// Use a relative URI
			authResponse = AuthenticationResponseParser.parse(URI.create("https:///?".concat(requestQuery)));
		} catch (ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		if (authResponse == null) {
			// FIXME
			throw new Exception("Unexpected error, try again");
		}
		AuthorizationCode authCode = Core.parseAuthorizationCode(authResponse);
		if (authCode != null) {
			OIDCTokenResponse tokenResponse = Core.doTokenRequest(Configuration.getProvider(), authCode);
			tokens = tokenResponse.getOIDCTokens();
		}
		if (tokens == null) {
			throw new Exception("Tokens null");
		}
		return getUserInfo(tokens);
		
	}
	
	public static UserInfo getUserInfo(OIDCTokens tokens) throws Exception {
		// if (token instanceof CustomOIDCToken) {
		// logger.log(Level.SEVERE, "At CustomOIDCToken");
		// CustomOIDCToken customToken = (CustomOIDCToken) token;
		// tokens = (OIDCTokens) customToken.getPrincipal();
		// }
		// From 3.1.3.5 to 3.1.3.6
		UserInfo userInfo = null;
		IDTokenClaimsSet tokensClaimSet = Core.verifyToken(Configuration.getProvider(), tokens);
		if (tokensClaimSet == null) {
			// FIXME Something went wrong, do something
		}
		userInfo = Core.getUserInfo(Configuration.getProvider(), tokens);
		if (userInfo == null) {
			throw new Exception("UserInfo null");
		}
		return userInfo;
	}
	
	public static Set<String> getPurposeAsRoles(UserInfo userInfo) {
		Set<String> roles = new HashSet<String>();
		if (userInfo.getClaim(PURPOSE_CLAIM) != null) {
			roles.add(userInfo.getStringClaim(PURPOSE_CLAIM));
		}
		return roles;
	}

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
			// FIXME Build it (how?)
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
}
