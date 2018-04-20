package mx.nic.rdap.auth.openidc.shiro.token;

import javax.servlet.ServletRequest;

import org.apache.shiro.authc.AuthenticationToken;

public class EndUserToken implements AuthenticationToken {

	/**
	 * Serial version
	 */
	private static final long serialVersionUID = -2935612351140092102L;
	
	private String id;
	private ServletRequest request;
	
	public EndUserToken(String id, ServletRequest request) {
		this.id = id;
		this.request = request;
	}

	@Override
	public Object getPrincipal() {
		// TODO Auto-generated method stub
		return id;
	}

	@Override
	public Object getCredentials() {
		// TODO Auto-generated method stub
		return null;
	}
	
	public ServletRequest getRequest() {
		return request;
	}

}
