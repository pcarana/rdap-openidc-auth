package mx.nic.rdap.auth.openidc;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import mx.nic.rdap.auth.openidc.exception.RequestException;
import mx.nic.rdap.auth.openidc.exception.ResponseException;
import mx.nic.rdap.auth.openidc.protocol.WebFingerRequest;

public class Configuration {

	public static final String USER_INFO_ATTR = "mx.nic.rdap.auth.openidc.info";
	
	// TODO Handle multiple providers
	private static Map<String, OpenIDCProvider> providersMap = new HashMap<>();
	// private static OpenIDCProvider provider;
	

	private Configuration() {
		
	}
	
	// public static OpenIDCProvider getProvider() {
	// return provider;
	// }

	// public static void setProvider(OpenIDCProvider provider) {
	// Configuration.provider = provider;
	// }

	public static void initProviders(List<OpenIDCProvider> providers) {
		for (OpenIDCProvider prov : providers) {
			URI uri;
			try {
				uri = new URI(prov.getProviderURI());
				String host = uri.getHost();
				if (host == null) {
					throw new URISyntaxException(uri.toString(), "Invalid Host URI");
				}
				if (uri.getPort() > 0) {
					host = host + ":" + uri.getPort();
				}
				AuthenticationFlow.updateProviderMetadata(prov);
				providersMap.put(host, prov);

			} catch (URISyntaxException | RequestException | ResponseException e) {
				throw new RuntimeException(e);
			}

		}
	}

	public static OpenIDCProvider getProvider(WebFingerRequest webfingerRequest) {
		return providersMap.get(webfingerRequest.getHost());
	}

}
