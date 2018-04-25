package mx.nic.rdap.auth.openidc.shiro;

import java.util.Set;

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
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;

import mx.nic.rdap.auth.openidc.AuthenticationFlow;
import mx.nic.rdap.auth.openidc.Configuration;
import mx.nic.rdap.auth.openidc.OpenIDCProvider;
import mx.nic.rdap.auth.openidc.exception.RequestException;
import mx.nic.rdap.auth.openidc.exception.ResponseException;
import mx.nic.rdap.auth.openidc.shiro.token.CustomOIDCToken;
import mx.nic.rdap.auth.openidc.shiro.token.UserInfoToken;

public class SecurityRealm extends AuthorizingRealm {
	
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
		try {
			AuthenticationFlow.updateProviderMetadata(provider);
		} catch (RequestException | ResponseException e) {
			throw new RuntimeException(e.getMessage(), e);
		}
	}

	@Override
	public boolean supports(AuthenticationToken token) {
		return token != null && (token instanceof UserInfoToken || token instanceof CustomOIDCToken);
	}

	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		UserInfo userInfo = (UserInfo) principals.getPrimaryPrincipal();
		Set<String> roles = AuthenticationFlow.getPurposeAsRoles(userInfo);
		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo(roles);
		return info;
	}

	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		if (token instanceof CustomOIDCToken) {
			CustomOIDCToken customToken = (CustomOIDCToken) token;
			OIDCTokens oidcTokens = (OIDCTokens) customToken.getCredentials();
			// Now the token will be a UserInfoToken
			try {
				UserInfo userInfo = AuthenticationFlow.getUserInfoFromToken(oidcTokens, Configuration.getProvider());
				token = new UserInfoToken(userInfo);
			} catch (RequestException | ResponseException e) {
				throw new AuthenticationException(e.getMessage(), e);
			}
		}
		// It's a UserInfoToken instance
		
		// If there's no principal, then something went wrong authenticating it
		if (token.getPrincipal() == null) {
			throw new IncorrectCredentialsException("Failed login");
		}
		AuthenticationInfo authInfo = new SimpleAuthenticationInfo(token.getPrincipal(), token.getCredentials(),
				getName());
		return authInfo;
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
