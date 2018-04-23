package mx.nic.rdap.auth.openidc;

import java.net.URI;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;

import mx.nic.rdap.auth.openidc.protocol.Core;

public class Authentication {

	public static Logger logger = Logger.getLogger(Authentication.class.getName());

	private Authentication() {
		// Empty
	}

	public static UserInfo validateAuthCode(String requestQuery) throws Exception {
		OIDCTokens tokens = null;
		logger.log(Level.SEVERE, "At AuthResponseToken");
		AuthenticationResponse authResponse = null;
		try {
			// Use a relative URI
			authResponse = AuthenticationResponseParser.parse(URI.create("https:///?".concat(requestQuery)));
		} catch (ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		if (authResponse == null) {
			// FIXME
			throw new Exception("Unexpected error, try again");
		}
		AuthorizationCode authCode = Core.parseAuthorizationCode(authResponse);
		if (authCode != null) {
			OIDCTokenResponse tokenResponse = Core.doTokenRequest(Configuration.getProvider(), authCode);
			tokens = tokenResponse.getOIDCTokens();
		}
		if (tokens == null) {
			throw new Exception("Tokens null");
		}
		return getUserInfo(tokens);
		
	}
	
	public static UserInfo getUserInfo(OIDCTokens tokens) throws Exception {
		// if (token instanceof CustomOIDCToken) {
		// logger.log(Level.SEVERE, "At CustomOIDCToken");
		// CustomOIDCToken customToken = (CustomOIDCToken) token;
		// tokens = (OIDCTokens) customToken.getPrincipal();
		// }
		// From 3.1.3.5 to 3.1.3.6
		UserInfo userInfo = null;
		IDTokenClaimsSet tokensClaimSet = Core.verifyToken(Configuration.getProvider(), tokens);
		if (tokensClaimSet == null) {
			// FIXME Something went wrong, do something
		}
		userInfo = Core.getUserInfo(Configuration.getProvider(), tokens);
		if (userInfo == null) {
			throw new Exception("UserInfo null");
		}
		return userInfo;
	}
}
