package mx.nic.rdap.auth.openidc.shiro;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.web.filter.authc.AuthenticatingFilter;

import com.nimbusds.jwt.JWT;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;

import mx.nic.rdap.auth.openidc.AuthenticationFlow;
import mx.nic.rdap.auth.openidc.Configuration;
import mx.nic.rdap.auth.openidc.OpenIDCProvider;
import mx.nic.rdap.auth.openidc.exception.RequestException;
import mx.nic.rdap.auth.openidc.exception.ResponseException;
import mx.nic.rdap.auth.openidc.protocol.Discovery;
import mx.nic.rdap.auth.openidc.shiro.token.CustomOIDCToken;
import mx.nic.rdap.auth.openidc.shiro.token.UserInfoToken;

public class IdentifierFilter extends AuthenticatingFilter {

	public static final String ID_PARAM = "id";
	public static final String ID_TOKEN_PARAM = "id_token";
	public static final String ACCESS_TOKEN_PARAM = "access_token";

	private static final Logger logger = Logger.getLogger(IdentifierFilter.class.getName());

	@Override
	protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
		if (isValidParam(request, ID_PARAM) && !isValidParam(request, ID_TOKEN_PARAM)
				&& !isValidParam(request, ACCESS_TOKEN_PARAM) && !isValidParam(request, "code")
				&& !isValidParam(request, "state")) {

			String userId = request.getParameter(ID_PARAM).trim();
			OpenIDCProvider provider = Discovery.discoverProvider(userId);
			if (provider == null) {
				HttpServletResponse httpResponse = (HttpServletResponse) response;
				httpResponse.sendError(HttpServletResponse.SC_NOT_IMPLEMENTED, "OpenId Provider not supported");
				return false;
			}
			String location = AuthenticationFlow.getAuthenticationLocation(userId, request, provider);
			HttpServletResponse httpResponse = (HttpServletResponse) response;
			httpResponse.sendRedirect(location);
			return false;
		}

		try {
			return super.preHandle(request, response);
		} catch (URISyntaxException e) {
			HttpServletResponse httpResponse = (HttpServletResponse) response;
			httpResponse.sendError(HttpServletResponse.SC_NOT_IMPLEMENTED, e.getMessage());
			return false;
		} catch (Exception e) {
			// Handle expected exceptions
			if (e instanceof ResponseException) {
				ResponseException responseException = (ResponseException) e;
				HttpServletResponse httpResponse = (HttpServletResponse) response;
				httpResponse.sendError(responseException.getCode(), responseException.getMessage());
				return false;
			}
			throw e;
		}
	}

	@Override
	protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) throws Exception {
		// TODO The issuer MAY be obtained from the referer, just to know where to
		// validate tokens
		if (request.getAttribute(Configuration.USER_INFO_ATTR) != null) {
			return new UserInfoToken(request);
		}

		// FIXME The access_token also may be at the Authorization Header (value =
		// "Bearer <the_code>")
		if (request.getParameter(ID_TOKEN_PARAM) != null && request.getParameter(ACCESS_TOKEN_PARAM) != null) {
			try {
				Decoder decoder = Base64.getUrlDecoder();
				String idTokenString = new String(decoder.decode(request.getParameter(ID_TOKEN_PARAM).trim()),
						StandardCharsets.UTF_8);
				String accessTokenString = new String(decoder.decode(request.getParameter(ACCESS_TOKEN_PARAM).trim()),
						StandardCharsets.UTF_8);

				return createTokenFromIdAndAccessToken(idTokenString, accessTokenString);
			} catch (IllegalArgumentException e) {
				throw new ResponseException(HttpServletResponse.SC_BAD_REQUEST, "Invalid token parameters", e);
			}

		}

		return null;
	}

	private AuthenticationToken createTokenFromIdAndAccessToken(String idTokenString, String accessTokenString)
			throws ResponseException {
		CustomOIDCToken customOIDCToken = new CustomOIDCToken(idTokenString, accessTokenString);
		OpenIDCProvider discoverProvider;
		OIDCTokens oidcTokens = customOIDCToken.getOidcTokens();
		JWT idToken = oidcTokens.getIDToken();
		try {
			if (idToken == null || idToken.getJWTClaimsSet() == null) {
				throw new ResponseException(HttpServletResponse.SC_BAD_REQUEST, "Invalid TOKEN parameters");
			}
		} catch (ParseException e1) {
			throw new ResponseException(HttpServletResponse.SC_BAD_REQUEST, "Invalid TOKEN parameters");
		}
		try {
			discoverProvider = Discovery.discoverProvider(idToken.getJWTClaimsSet().getIssuer());
			if (discoverProvider == null) {
				throw new ResponseException(HttpServletResponse.SC_BAD_REQUEST,
						"No discovery provider for issuer: " + idToken.getJWTClaimsSet().getIssuer());
			}
		} catch (URISyntaxException | ParseException e) {
			throw new ResponseException(HttpServletResponse.SC_BAD_REQUEST, e.getMessage());
		}

		try {
			UserInfo userInfo = AuthenticationFlow.getUserInfoFromToken(oidcTokens, discoverProvider);
			return new UserInfoToken(userInfo);
		} catch (RequestException e) {
			throw new AuthenticationException(e.getMessage(), e);
		} catch (ResponseException e) {
			throw e;
		}

	}

	@Override
	protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
		if (!isLoginRequest(request, response)) {
			return true;
		}
		return executeLogin(request, response);
	}

	@Override
	protected final boolean isLoginRequest(ServletRequest request, ServletResponse response) {
		return hasValidParams(request);
	}

	/**
	 * Has the parameter "id", or the parameters "id_token" and "access_token", or
	 * the attribute Configuration.USER_INFO_ATTR
	 * 
	 * @param request
	 * @return
	 */
	private boolean hasValidParams(ServletRequest request) {
		return isValidParam(request, ID_PARAM)
				|| (isValidParam(request, ID_TOKEN_PARAM) && isValidParam(request, ACCESS_TOKEN_PARAM))
				|| request.getAttribute(Configuration.USER_INFO_ATTR) != null;
	}

	private boolean isValidParam(ServletRequest request, String parameterId) {
		String[] idValue = request.getParameterValues(parameterId);
		return idValue != null && idValue.length == 1 && !idValue[0].trim().isEmpty();
	}

	protected boolean onLoginFailure(AuthenticationToken token, AuthenticationException e, ServletRequest request,
			ServletResponse response) {
		HttpServletResponse httpResponse = (HttpServletResponse) response;
		if (e.getCause() != null && e.getCause() instanceof ResponseException) {
			ResponseException resp = (ResponseException) e.getCause();
			int code = resp.getCode();
			String message = resp.getMessage();
			try {
				if (message != null && !message.trim().isEmpty()) {
					httpResponse.sendError(code, message);
				} else {
					httpResponse.sendError(code);
				}
			} catch (IOException e1) {
				logger.log(Level.SEVERE, e.getMessage(), e1);
			}
		} else {
			logger.log(Level.WARNING, e.getMessage(), e);
			try {
				httpResponse.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
			} catch (IOException e1) {
				logger.log(Level.SEVERE, e.getMessage(), e1);
			}
		}
		return false;
	}

}
