package mx.nic.rdap.auth.openidc.shiro.token;

import java.net.URI;

import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;

import org.apache.shiro.authc.AuthenticationToken;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;

public class AuthResponseToken implements AuthenticationToken {

	/**
	 * Serial version
	 */
	private static final long serialVersionUID = -5267069051564153505L;

	private AuthenticationResponse authenticationResponse;

	public AuthResponseToken(ServletRequest request) {
		HttpServletRequest httpRequest = (HttpServletRequest) request;
		try {
			this.authenticationResponse = AuthenticationResponseParser.parse(URI
					.create(httpRequest.getRequestURL().append("?").append(httpRequest.getQueryString()).toString()));
		} catch (ParseException e) {
			// Nothing to do FIXME
		}
	}

	@Override
	public Object getPrincipal() {
		// TODO Auto-generated method stub
		return authenticationResponse;
	}

	@Override
	public Object getCredentials() {
		// TODO Auto-generated method stub
		return authenticationResponse.getState();
	}

}
