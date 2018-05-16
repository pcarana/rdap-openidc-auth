package mx.nic.rdap.auth.openidc.shiro.token;

import org.apache.shiro.authc.AuthenticationToken;

import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;

public class CustomOIDCToken implements AuthenticationToken {

	/**
	 * Serial version
	 */
	private static final long serialVersionUID = -1027558836698344937L;
	
	private OIDCTokens oidcTokens;
	
	public CustomOIDCToken(String idToken, String accessToken) {
		AccessToken accessTokenObj = new BearerAccessToken(accessToken);
		oidcTokens = new OIDCTokens(idToken, accessTokenObj, null);
	}

	@Override
	public Object getPrincipal() {
		return oidcTokens;
	}

	@Override
	public Object getCredentials() {
		return oidcTokens;
	}

	public OIDCTokens getOidcTokens() {
		return oidcTokens;
	}
}
