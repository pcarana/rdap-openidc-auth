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
import net.minidev.json.JSONObject;

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
			throw new RequestException(e.getMessage(), e);
		}
		if (!httpResponse.indicatesSuccess()) {
			throw new ResponseException(httpResponse.getStatusCode(),
					providerURI.concat(" issuer returned HTTP Code ").concat("" + httpResponse.getStatusCode()));
		}
		try {
			return OIDCProviderMetadata.parse(httpResponse.getContentAsJSONObject());
		} catch (ParseException e) {
			// FIXME There's a known issue when parsing Gluu server data, this an ugly patch =/
			try {
				JSONObject json = httpResponse.getContentAsJSONObject();
				json.replace("frontchannel_logout_supported",
						Boolean.parseBoolean(json.getAsString("frontchannel_logout_supported")));
				return OIDCProviderMetadata.parse(json);
			} catch (ParseException e2) {
				// This will be another unexpected problem
				logger.log(Level.SEVERE, e.getMessage(), e);
				throw new ResponseException(e.getMessage(), e);
			}
		}
	}

}
