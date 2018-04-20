package mx.nic.rdap.auth.openidc.shiro.exception;

import org.apache.shiro.authc.AuthenticationException;

public class RedirectException extends AuthenticationException {

	/**
	 * Serial version
	 */
	private static final long serialVersionUID = 6143153100128416498L;
	
	private String location;

	public RedirectException(String location) {
		this.setLocation(location);
	}

	public RedirectException(Throwable cause) {
		super(cause);
	}

	public String getLocation() {
		return location;
	}

	public void setLocation(String location) {
		this.location = location;
	}

}
