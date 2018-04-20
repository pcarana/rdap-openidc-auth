package mx.nic.rdap.auth.openidc.shiro;

import java.net.URI;
import java.util.Collections;
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

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;

import mx.nic.rdap.auth.openidc.protocol.Core;
import mx.nic.rdap.auth.openidc.protocol.Discovery;
import mx.nic.rdap.auth.openidc.protocol.DynamicClientRegistration;
import mx.nic.rdap.auth.openidc.shiro.exception.RedirectException;
import mx.nic.rdap.auth.openidc.shiro.token.AuthResponseToken;
import mx.nic.rdap.auth.openidc.shiro.token.CustomOIDCToken;
import mx.nic.rdap.auth.openidc.shiro.token.EndUserToken;

public class SecurityRealm extends AuthorizingRealm {

	private static Logger logger = Logger.getLogger(SecurityRealm.class.getName());

	protected String clientUri;
	protected String clientAccessToken;
	protected String clientId;
	protected String clientSecret;

	public SecurityRealm() {
		super();
		this.setCredentialsMatcher(new AllowAllCredentialsMatcher());
	}

	@Override
	public boolean supports(AuthenticationToken token) {
		if (token != null) {
			return token instanceof EndUserToken || token instanceof AuthResponseToken
					|| token instanceof CustomOIDCToken;
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
			String redirectUrl = null;
			StringBuffer sb = new StringBuffer();
			if (userToken.getRequest() instanceof HttpServletRequest) {
				HttpServletRequest request = (HttpServletRequest) userToken.getRequest();
				sb.append(request.getRequestURL());
				if (request.getQueryString() != null) {
					sb.append("?").append(request.getQueryString());
				}
				redirectUrl = sb.toString();
			} else {
				// FIXME Build it (how?)
//				ServletRequest request = userToken.getRequest();
//				sb.append(request.getScheme());
//				sb.append("://");
//				sb.append(request.getServerName());
//				if (request.getServerPort() > 0) {
//					sb.append(request.getServerPort());
//				}
//				// Apparently the path is not available
//				sb.append();
			}
			
			URI location = Core.getAuthenticationURI(clientId, providerMetadata, redirectUrl);
			logger.log(Level.SEVERE, "Before redirect to " + location.toString());
			throw new RedirectException(location.toString());
		}
		OIDCTokens tokens = null;
		if (token instanceof AuthResponseToken) {
			logger.log(Level.SEVERE, "At AuthResponseToken");
			AuthResponseToken authToken = (AuthResponseToken) token;
			if (authToken.getPrincipal() == null) {
				throw new AuthenticationException("Unexpected error, try again");
			}
			AuthorizationCode authCode = Core.parseAuthorizationCode((AuthenticationResponse) authToken.getPrincipal());
			if (authCode != null) {
				OIDCTokenResponse tokenResponse = Core.doTokenRequest(clientId, clientSecret, authCode);
				tokens = tokenResponse.getOIDCTokens();
			}
		}
		UserInfo userInfo = null;
		if (token instanceof CustomOIDCToken) {
			logger.log(Level.SEVERE, "At CustomOIDCToken");
			CustomOIDCToken customToken = (CustomOIDCToken) token;
			tokens = (OIDCTokens) customToken.getPrincipal();
		}
		if (tokens != null) {
			// From 3.1.3.5 to 3.1.3.6
			IDTokenClaimsSet tokensClaimSet = Core.verifyToken(clientId, tokens);
			if (tokensClaimSet != null) {
				// FIXME Somthing went wrong, do something
			}
			userInfo = Core.getUserInfo(tokens);
		}
		if (userInfo == null) {
			throw new IncorrectCredentialsException("Failed login");
		}
		AuthenticationInfo authInfo = new SimpleAuthenticationInfo(userInfo.getSubject().getValue(), userInfo,
				getName());
		return authInfo;
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

}
