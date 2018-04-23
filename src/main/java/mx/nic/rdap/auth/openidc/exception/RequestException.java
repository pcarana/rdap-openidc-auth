package mx.nic.rdap.auth.openidc.exception;

/**
 * Encapsulates any exception related to an OpenID Connect Request
 *
 */
public class RequestException extends Exception {

	/**
	 * Serial version
	 */
	private static final long serialVersionUID = -8076308690755109271L;

	public RequestException() {	}

	public RequestException(String message) {
		super(message);
	}

	public RequestException(Throwable cause) {
		super(cause);
	}

	public RequestException(String message, Throwable cause) {
		super(message, cause);
	}

}
