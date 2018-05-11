package mx.nic.rdap.auth.openidc.protocol;

import java.net.URI;
import java.net.URISyntaxException;

public class IssuerDiscoveryUtils {

	private IssuerDiscoveryUtils() {
		// no code;
	}

	public static WebFingerRequest getWebFingerRequest(String userId) throws URISyntaxException {
		if (userId == null || userId.trim().isEmpty()) {
			throw new URISyntaxException("null or empty", "Insert a valid id");
		}

		userId = userId.trim();
		URI uri = new URI(userId);

		String scheme = uri.getScheme();
		if (scheme == null) {
			return normalizeNoScheme(userId);
		}

		if (scheme.equalsIgnoreCase("https")) {
			return normalize(uri, false, scheme);
		}

		if (!scheme.equalsIgnoreCase("acct")) {
			// unknown scheme, if its a protocol scheme throw an error, if not add https://
			if (userId.contains("://")) {
				throw new URISyntaxException(userId, "Scheme '" + scheme + "' out of specification.");
			}
			return normalizeNoScheme(userId);
		}

		if (uri.getFragment() != null) {
			throw new URISyntaxException(userId,
					"Invalid userId. 'acct' URI scheme syntax is: 'acct:userpart@host[:port]' ");
		}

		uri = new URI("acct://" + uri.getRawSchemeSpecificPart());
		if (!isAcctScheme(uri)) {
			throw new URISyntaxException(userId,
					"Invalid userId. 'acct' URI scheme syntax is: 'acct:userpart@host[:port]' ");
		}

		return normalize(uri, true, scheme);
	}

	private static WebFingerRequest normalizeNoScheme(String userId) throws URISyntaxException {

		URI uri = new URI("https://" + userId);
		return normalize(uri, true, userId);
	}

	private static WebFingerRequest normalize(URI uri, boolean tryAsAcct, String userId) throws URISyntaxException {
		String host = uri.getHost();

		if (host == null) {
			throw new URISyntaxException(userId, "Invalid Id");
		}

		if (uri.getPort() > 0) {
			host = host + ":" + uri.getPort();
		}

		String resource;
		if (tryAsAcct && isAcctScheme(uri)) {
			resource = "acct:" + uri.getRawAuthority();
		} else {
			resource = uri.getScheme() + ":" + uri.getRawSchemeSpecificPart();
		}

		return new WebFingerRequest(resource, host);

	}

	private static boolean isAcctScheme(URI uri) {
		if (uri.getUserInfo() == null || uri.getUserInfo().isEmpty()) {
			return false;
		}

		if (uri.getPath() != null && !uri.getPath().isEmpty()) {
			return false;
		}

		if (uri.getQuery() != null && !uri.getQuery().isEmpty()) {
			return false;
		}

		if (uri.getFragment() != null && !uri.getFragment().isEmpty()) {
			return false;
		}

		return true;
	}

}
