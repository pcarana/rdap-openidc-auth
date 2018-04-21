package mx.nic.rdap.auth.openidc;

public class Configuration {

	public static final String USER_INFO_ATTR = "mx.nic.rdap.auth.openidc.info";
	
	private static String clientUri;
	private static String clientAccessToken;
	private static String clientId;
	private static String clientSecret;
	private static String clientCallbackURI;
	
	private Configuration() {
		// Empty
	}

	public static String getClientUri() {
		return clientUri;
	}

	public static void setClientUri(String clientUri) {
		Configuration.clientUri = clientUri;
	}

	public static String getClientAccessToken() {
		return clientAccessToken;
	}

	public static void setClientAccessToken(String clientAccessToken) {
		Configuration.clientAccessToken = clientAccessToken;
	}

	public static String getClientId() {
		return clientId;
	}

	public static void setClientId(String clientId) {
		Configuration.clientId = clientId;
	}

	public static String getClientSecret() {
		return clientSecret;
	}

	public static void setClientSecret(String clientSecret) {
		Configuration.clientSecret = clientSecret;
	}

	public static String getClientCallbackURI() {
		return clientCallbackURI;
	}

	public static void setClientCallbackURI(String clientCallbackURI) {
		Configuration.clientCallbackURI = clientCallbackURI;
	}

}
