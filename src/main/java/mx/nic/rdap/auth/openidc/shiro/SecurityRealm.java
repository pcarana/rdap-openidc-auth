package mx.nic.rdap.auth.openidc.shiro;

import java.net.URI;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
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
import mx.nic.rdap.auth.openidc.protocol.Core;
import mx.nic.rdap.auth.openidc.protocol.Discovery;
import mx.nic.rdap.auth.openidc.protocol.DynamicClientRegistration;
import mx.nic.rdap.auth.openidc.shiro.exception.RedirectException;
import mx.nic.rdap.auth.openidc.shiro.token.CustomOIDCToken;
import mx.nic.rdap.auth.openidc.shiro.token.EndUserToken;
import mx.nic.rdap.auth.openidc.shiro.token.UserInfoToken;

public class SecurityRealm extends AuthorizingRealm {

	private static Logger logger = Logger.getLogger(SecurityRealm.class.getName());

	protected String clientUri;
	protected String clientAccessToken;
	protected String clientId;
	protected String clientSecret;
	protected String clientCallbackURI;

	public SecurityRealm() {
		super();
		this.setCredentialsMatcher(new AllowAllCredentialsMatcher());
	}

	@Override
	public void onInit() {
		Configuration.setClientUri(clientUri);
		Configuration.setClientAccessToken(clientAccessToken);
		Configuration.setClientId(clientId);
		Configuration.setClientSecret(clientSecret);
		Configuration.setClientCallbackURI(clientCallbackURI);
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
		// TODO Auto-generated method stub
		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo(Collections.emptySet());
		info.setStringPermissions(null);
		return info;
	}

	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		logger.log(Level.SEVERE, "At doGetAuthenticationInfo" + token.toString());
		if (token instanceof EndUserToken) {
			// From 3.1.3 to 3.1.3.3
			EndUserToken userToken = (EndUserToken) token;
			DynamicClientRegistration.register(clientUri, clientAccessToken, clientId, clientSecret);
			String providerURI = Discovery.discoverProvider(userToken.getPrincipal().toString());
			OIDCProviderMetadata providerMetadata = Discovery.getProviderMetadata(providerURI);
			String originUri = getOriginURI(userToken.getRequest());
			URI location = Core.getAuthenticationURI(clientId, providerMetadata, clientCallbackURI, originUri);
			logger.log(Level.SEVERE, "Before redirect to " + location.toString());
			throw new RedirectException(location.toString());
		}
		UserInfo userInfo = null;
		if (token instanceof UserInfoToken) {
			userInfo = (UserInfo) token.getPrincipal();
		}
		if (userInfo == null) {
			throw new IncorrectCredentialsException("Failed login");
		}

		AuthenticationInfo authInfo = new SimpleAuthenticationInfo(userInfo.getSubject().getValue(), userInfo,
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

	public String getClientUri() {
		return clientUri;
	}

	public void setClientUri(String clientUri) {
		this.clientUri = clientUri;
	}

	public String getClientAccessToken() {
		return clientAccessToken;
	}

	public void setClientAccessToken(String clientAccessToken) {
		this.clientAccessToken = clientAccessToken;
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

}
