package mx.nic.rdap.auth.openidc.shiro;

import java.util.List;
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

import mx.nic.rdap.auth.openidc.AuthenticationFlow;
import mx.nic.rdap.auth.openidc.Configuration;
import mx.nic.rdap.auth.openidc.OpenIDCProvider;
import mx.nic.rdap.auth.openidc.shiro.token.UserInfoToken;

public class SecurityRealm extends AuthorizingRealm {

	protected List<OpenIDCProvider> providers;

	public SecurityRealm() {
		super();
		this.setCredentialsMatcher(new AllowAllCredentialsMatcher());
	}

	@Override
	public void onInit() {
		Configuration.initProviders(providers);
	}

	@Override
	public boolean supports(AuthenticationToken token) {
		return token != null && token instanceof UserInfoToken;
	}

	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		if (principals.fromRealm(getName()).isEmpty()) {
			return null;
		}
		UserInfo userInfo = (UserInfo) principals.getPrimaryPrincipal();
		Set<String> roles = AuthenticationFlow.getPurposeAsRoles(userInfo);
		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo(roles);
		return info;
	}

	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		// If there's no principal, then something went wrong authenticating it
		if (token.getPrincipal() == null) {
			throw new IncorrectCredentialsException("Failed login");
		}
		AuthenticationInfo authInfo = new SimpleAuthenticationInfo(token.getPrincipal(), token.getCredentials(),
				getName());
		return authInfo;
	}

	public List<OpenIDCProvider> getProviders() {
		return providers;
	}

	public void setProviders(List<OpenIDCProvider> providers) {
		this.providers = providers;
	}

}
