package mx.nic.rdap.auth.openidc.servlet;

public class TokenQueryParams {

	private String id;
	private boolean isRefresh;
	private String refreshToken;
	private String code;
	private String state;

	public TokenQueryParams(String id, boolean isRefresh, String refreshToken, String code, String state) {
		super();
		this.id = id;
		this.isRefresh = isRefresh;
		this.refreshToken = refreshToken;
		this.code = code;
		this.state = state;
	}

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public boolean isRefresh() {
		return isRefresh;
	}

	public void setRefresh(boolean isRefresh) {
		this.isRefresh = isRefresh;
	}

	public String getRefreshToken() {
		return refreshToken;
	}

	public void setRefreshToken(String refreshToken) {
		this.refreshToken = refreshToken;
	}

	public String getCode() {
		return code;
	}

	public void setCode(String code) {
		this.code = code;
	}

	public String getState() {
		return state;
	}

	public void setState(String state) {
		this.state = state;
	}


	public boolean isValidQueryParam() {
		if (id == null && code == null) {
			return false;
		} else if (code != null) {
			if (id == null || id.isEmpty() || code.isEmpty() || state == null || state.isEmpty()) {
				return false;
			}
		}

		return true;
	}

	public boolean isTokenRequest() {
		return id != null && refreshToken == null && code == null && state == null;
	}

	public boolean isTokenRefreshRequest() {
		return id != null && refreshToken != null && code == null && state == null;
	}

	public boolean isOPResponse() {
		return id != null && refreshToken == null && code != null && state != null;
	}





}
