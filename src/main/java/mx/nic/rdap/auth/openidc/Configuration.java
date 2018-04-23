package mx.nic.rdap.auth.openidc;

public class Configuration {

	public static final String USER_INFO_ATTR = "mx.nic.rdap.auth.openidc.info";
	
	// TODO Handle multiple providers
	//private static Map<String, OpenIDCProvider> providersMap;
	private static OpenIDCProvider provider;
	
	private Configuration() {
		
	}
	
//	TODO Handle multiple providers
//	public static void addProvider(String providerURI, String clientId, String clientSecret, String callbackURI,
//			OIDCProviderMetadata metadata) {
//		OpenIDCProvider oiOpenIDCProvider = new OpenIDCProvider(clientId, clientSecret, callbackURI, metadata);
//		providersMap.put(providerURI, oiOpenIDCProvider);
//	}

	public static OpenIDCProvider getProvider() {
		return provider;
	}

	public static void setProvider(OpenIDCProvider provider) {
		Configuration.provider = provider;
	}

}
