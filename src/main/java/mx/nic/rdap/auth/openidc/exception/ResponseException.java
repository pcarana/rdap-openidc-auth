package mx.nic.rdap.auth.openidc.exception;

/**
 * Encapsulates any exception related to an OpenID Connect Response
 *
 */
public class ResponseException extends Exception {

	/**
	 * Serial version
	 */
	private static final long serialVersionUID = -4770033484894753235L;

	public ResponseException() { }

	public ResponseException(String message) {
		super(message);
	}

	public ResponseException(Throwable cause) {
		super(cause);
	}

	public ResponseException(String message, Throwable cause) {
		super(message, cause);
	}

}
