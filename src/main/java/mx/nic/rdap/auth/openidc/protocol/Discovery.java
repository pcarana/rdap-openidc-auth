package mx.nic.rdap.auth.openidc.protocol;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderConfigurationRequest;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

import mx.nic.rdap.auth.openidc.Configuration;
import mx.nic.rdap.auth.openidc.exception.RequestException;
import mx.nic.rdap.auth.openidc.exception.ResponseException;

public class Discovery {

	private static Logger logger = Logger.getLogger(Discovery.class.getName());

	private Discovery() {
		// Empty
	}

	/**
	 * Discover a user OP provider based on its ID
	 * 
	 * @param userId
	 * @return
	 */
	public static String discoverProvider(String userId) {
		// FIXME Not implemented by the library, use manually configured URI
		String providerUri = Configuration.getProvider().getProviderURI();
		return providerUri;
	}

	/**
	 * Get the provider metadata based on its URI (issuer URI)
	 * 
	 * @param providerURI
	 * @return
	 * @throws RequestException
	 * @throws ResponseException
	 */
	public static OIDCProviderMetadata getProviderMetadata(String providerURI)
			throws RequestException, ResponseException {
		Issuer issuer = new Issuer(providerURI);
		OIDCProviderConfigurationRequest request = new OIDCProviderConfigurationRequest(issuer);
		HTTPResponse httpResponse = null;
		try {
			httpResponse = request.toHTTPRequest().send();
		} catch (IOException e) {
			logger.log(Level.SEVERE, e.getMessage(), e);
			throw new RequestException(e.getMessage(), e);
		}
		if (!httpResponse.indicatesSuccess()) {
			throw new ResponseException(
					providerURI.concat(" issuer returned HTTP Code ").concat("" + httpResponse.getStatusCode()));
		}
		try {
			return OIDCProviderMetadata.parse(httpResponse.getContentAsJSONObject());
		} catch (ParseException e) {
			logger.log(Level.SEVERE, e.getMessage(), e);
			throw new ResponseException(e.getMessage(), e);
		}
	}

}
