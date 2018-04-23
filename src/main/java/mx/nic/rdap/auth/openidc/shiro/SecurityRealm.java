package mx.nic.rdap.auth.openidc.shiro;

import java.net.URI;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.credential.AllowAllCredentialsMatcher;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

import mx.nic.rdap.auth.openidc.Configuration;
import mx.nic.rdap.auth.openidc.OpenIDCProvider;
import mx.nic.rdap.auth.openidc.protocol.Core;
import mx.nic.rdap.auth.openidc.protocol.Discovery;
import mx.nic.rdap.auth.openidc.shiro.exception.RedirectException;
import mx.nic.rdap.auth.openidc.shiro.token.CustomOIDCToken;
import mx.nic.rdap.auth.openidc.shiro.token.EndUserToken;
import mx.nic.rdap.auth.openidc.shiro.token.UserInfoToken;

public class SecurityRealm extends AuthorizingRealm {

	private static Logger logger = Logger.getLogger(SecurityRealm.class.getName());

	private static final String PURPOSE_CLAIM = "purpose";
	
	protected String clientId;
	protected String clientSecret;
	protected String clientCallbackURI;
	protected String providerURI;

	public SecurityRealm() {
		super();
		this.setCredentialsMatcher(new AllowAllCredentialsMatcher());
	}

	@Override
	public void onInit() {
		OpenIDCProvider provider = new OpenIDCProvider(clientId, clientSecret, clientCallbackURI, providerURI);
		Configuration.setProvider(provider);
	}

	@Override
	public boolean supports(AuthenticationToken token) {
		if (token != null) {
			return token instanceof EndUserToken || token instanceof UserInfoToken || token instanceof CustomOIDCToken;
		}
		return false;
	}

	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		UserInfo userInfo = (UserInfo) principals.getPrimaryPrincipal();
		Set<String> roles = new HashSet<String>();
		if (userInfo.getClaim(PURPOSE_CLAIM) != null) {
			roles.add(userInfo.getStringClaim(PURPOSE_CLAIM));
		}
		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo(roles);
		return info;
	}

	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		logger.log(Level.SEVERE, "At doGetAuthenticationInfo" + token.toString());
		if (token instanceof EndUserToken) {
			// From 3.1.3 to 3.1.3.3
			EndUserToken userToken = (EndUserToken) token;
			//DynamicClientRegistration.register(clientUri, clientAccessToken, clientId, clientSecret);
			String providerURI = Discovery.discoverProvider(userToken.getPrincipal().toString());
			OpenIDCProvider provider = Configuration.getProvider();
			if (provider.getMetadata() == null) {
				OIDCProviderMetadata metadata = Discovery.getProviderMetadata(providerURI);
				provider.setMetadata(metadata);
			}
			// TODO Handle multiple providers
//			OpenIDCProvider provider = Configuration.getProvidersMap().get(providerURI);
//			if (provider == null) {
//				OIDCProviderMetadata metadata = Discovery.getProviderMetadata(providerURI);
//				Configuration.addProvider(providerURI, clientId, clientSecret, clientCallbackURI, metadata);
//			}
			String originUri = getOriginURI(userToken.getRequest());
			Set<String> scope = new HashSet<String>();
			scope.add("openid");
			//scope.add("purpose");
			scope.add("email");
			URI location = Core.getAuthenticationURI(provider, scope, originUri);
			logger.log(Level.SEVERE, "Before redirect to " + location.toString());
			throw new RedirectException(location.toString());
		}
		if (token.getPrincipal() == null) {
			throw new IncorrectCredentialsException("Failed login");
		}
//		UserInfo userInfo = null;
//		if (token instanceof UserInfoToken) {
//			userInfo = (UserInfo) token.getPrincipal();
//		}
//		if (userInfo == null) {
//			throw new IncorrectCredentialsException("Failed login");
//		}

		AuthenticationInfo authInfo = new SimpleAuthenticationInfo(token.getPrincipal(), token.getCredentials(),
				getName());
		return authInfo;
	}

	private String getOriginURI(ServletRequest request) {
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
			// // Apparently the path is not available
			// sb.append();
		}
		return sb.toString();
	}

	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public String getClientSecret() {
		return clientSecret;
	}

	public void setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
	}

	public String getClientCallbackURI() {
		return clientSecret;
	}

	public void setClientCallbackURI(String clientCallbackURI) {
		this.clientCallbackURI = clientCallbackURI;
	}

	public String getProviderURI() {
		return providerURI;
	}

	public void setProviderURI(String providerURI) {
		this.providerURI = providerURI;
	}

}
