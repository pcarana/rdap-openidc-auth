package mx.nic.rdap.auth.openidc.shiro.token;

import javax.servlet.ServletRequest;

import org.apache.shiro.authc.AuthenticationToken;

import com.nimbusds.openid.connect.sdk.claims.UserInfo;

import mx.nic.rdap.auth.openidc.Configuration;

public class UserInfoToken implements AuthenticationToken {

	/**
	 * Serial version
	 */
	private static final long serialVersionUID = 758067304493495086L;

	private UserInfo userInfo;

	public UserInfoToken(ServletRequest request) {
		Object userInfoObj = request.getAttribute(Configuration.USER_INFO_ATTR);
		if (userInfoObj != null && userInfoObj instanceof UserInfo) {
			this.userInfo = (UserInfo) userInfoObj;
		}
	}

	public UserInfoToken(UserInfo userInfo) {
		this.userInfo = userInfo;
	}

	@Override
	public Object getPrincipal() {
		return userInfo.getSubject().getValue();
	}

	@Override
	public Object getCredentials() {
		return userInfo;
	}

}
