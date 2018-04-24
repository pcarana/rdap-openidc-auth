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

	/**
	 * Default value 500 "Internal server error"
	 */
	private int code = 500;
	
	public ResponseException() { }

	public ResponseException(String message) {
		super(message);
	}

	public ResponseException(int code, String message) {
		super(message);
		this.code = code;
	}

	public ResponseException(String message, Throwable cause) {
		super(message, cause);
	}

	public ResponseException(int code, String message, Throwable cause) {
		super(message, cause);
		this.code = code;
	}

	public int getCode() {
		return code;
	}

	public void setCode(int code) {
		this.code = code;
	}

}
