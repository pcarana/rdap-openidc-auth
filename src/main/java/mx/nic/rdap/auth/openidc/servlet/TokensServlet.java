package mx.nic.rdap.auth.openidc.servlet;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Base64.Encoder;

import javax.json.Json;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObjectBuilder;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenResponse;

import mx.nic.rdap.auth.openidc.AuthenticationFlow;
import mx.nic.rdap.auth.openidc.Configuration;
import mx.nic.rdap.auth.openidc.OpenIDCProvider;
import mx.nic.rdap.auth.openidc.exception.RequestException;
import mx.nic.rdap.auth.openidc.exception.ResponseException;
import net.minidev.json.JSONObject;

@WebServlet(name = "tokens", urlPatterns = { "/tokens" })
public class TokensServlet extends HttpServlet {

	private static final String ID_PARAM = "id";
	private static final String REFRESH_PARAM = "refresh";
	private static final String REFRESH_TOKEN_PARAM = "refresh_token";

	private static final String CODE_PARAM = "code";
	private static final String STATE_PARAM = "state";

	/**
	 * Serial version
	 */
	private static final long serialVersionUID = -3755516672887712201L;

	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response)
			throws IOException, ServletException {

		TokenQueryParams tokenParams = null;
		try {
			tokenParams = getTokenParams(request);
		} catch (IllegalArgumentException e) {
			response.sendError(HttpServletResponse.SC_BAD_REQUEST, e.getMessage());
			return;
		}
		if (!tokenParams.isValidQueryParam()) {
			response.sendError(HttpServletResponse.SC_BAD_REQUEST);
			return;
		}

		if (tokenParams.isTokenRequest()) {
			requestTokenProcess(request, response, tokenParams);
			return;
		} else if (tokenParams.isTokenRefreshRequest()) {
			requestRefreshToken(request, response, tokenParams);
			return;
		} else if (tokenParams.isOPResponse()) {
			processOPResponse(request, response, tokenParams);
			return;
		}

	}

	private static TokenQueryParams getTokenParams(HttpServletRequest request) {
		String id = sanitizeParameter(request.getParameter(ID_PARAM));
		String refresh = sanitizeParameter(request.getParameter(REFRESH_PARAM));
		String refreshToken = sanitizeParameter(request.getParameter(REFRESH_TOKEN_PARAM));
		String code = sanitizeParameter(request.getParameter(CODE_PARAM));
		String state = sanitizeParameter(request.getParameter(STATE_PARAM));

		boolean parseBoolean = Boolean.parseBoolean(refresh);

		if (refreshToken != null)
			refreshToken = new String(Base64.getUrlDecoder().decode(refreshToken), StandardCharsets.UTF_8);

		return new TokenQueryParams(id, parseBoolean, refreshToken, code, state);
	}

	private static String sanitizeParameter(String parameter) {
		if (parameter == null) {
			return null;
		}

		parameter = parameter.trim();
		if (parameter.isEmpty()) {
			return null;
		}

		return parameter;
	}

	private void requestTokenProcess(HttpServletRequest request, HttpServletResponse response,
			TokenQueryParams tokenParams) throws IOException {
		// TODO: discover OP with id

		OpenIDCProvider provider = Configuration.getProvider();
		String userId = tokenParams.getId();
		String location = AuthenticationFlow.getAuthenticationLocation(userId, request, provider);

		response.sendRedirect(location);

	}

	private void requestRefreshToken(HttpServletRequest request, HttpServletResponse response,
			TokenQueryParams tokenParams) throws IOException {
		OpenIDCProvider provider = Configuration.getProvider();
		try {
			TokenResponse tokenResponse = AuthenticationFlow.getTokenRefreshResponse(tokenParams.getRefreshToken(),
					provider);
			response.setContentType("application/json");
			if (tokenResponse != null && tokenResponse.indicatesSuccess()) {
				processRefreshTokenResponse(tokenResponse.toSuccessResponse().toJSONObject(), request, response);
			} else {
				if (tokenResponse != null) {
					TokenErrorResponse errorResponse = tokenResponse.toErrorResponse();
					ErrorObject errorObject = errorResponse.getErrorObject();
					if (errorObject != null && errorObject.getHTTPStatusCode() != 0) {
						if (errorObject.getDescription() != null) {
							response.sendError(errorObject.getHTTPStatusCode(), errorObject.getDescription());
						} else {
							response.sendError(errorObject.getHTTPStatusCode());
						}
					}
				}
			}
			return;
		} catch (RequestException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ResponseException e) {
			response.sendError(e.getCode(), e.getMessage());
			return;
		}

	}

	private void processRefreshTokenResponse(JSONObject json, HttpServletRequest request, HttpServletResponse response)
			throws IOException {
		JsonObjectBuilder object = Json.createObjectBuilder();
		JsonArrayBuilder arrBuilder = Json.createArrayBuilder();
		arrBuilder.add("rdap_level_0");
		arrBuilder.add("rdap_openidc_level_0");
		object.add("rdapConformance", arrBuilder);

		Encoder urlEncoder = Base64.getUrlEncoder();
		object.add("access_token",
				urlEncoder.encodeToString(json.getAsString("access_token").getBytes(StandardCharsets.UTF_8)));
		object.add("refresh_token",
				urlEncoder.encodeToString(json.getAsString("refresh_token").getBytes(StandardCharsets.UTF_8)));
		object.add("token_type", json.getAsString("token_type"));
		object.add("expires_in", json.getAsString("expires_in"));

		response.getWriter().print(object.build().toString());
	}


	private void processOPResponse(HttpServletRequest request, HttpServletResponse response,
			TokenQueryParams tokenParams) throws IOException, ServletException {

		String codeParam = tokenParams.getCode();
		String stateParam = tokenParams.getState();

		if (codeParam == null || codeParam.isEmpty() || stateParam == null || stateParam.isEmpty()) {
			response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Code param and/or state parameter is null");
			return;
		}

		String forwardURI = new com.nimbusds.jose.util.Base64(stateParam).decodeToString();
		if (forwardURI == null || forwardURI.isEmpty()) {
			// Invalid state, continue chain
			response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Code param and/or state parameter is null");
			return;
		}

		TokenResponse token = null;
		try {
			token = AuthenticationFlow.getTokenResponse(request.getQueryString(), Configuration.getProvider());
		} catch (Exception e) {
			// Translate to HTTP Codes
			if (e instanceof ResponseException) {
				ResponseException responseExc = (ResponseException) e;
				response.sendError(responseExc.getCode(), responseExc.getMessage());
				return;
			}
			throw new ServletException(e);
		}

		response.setContentType("application/json");
		if (token != null && token.indicatesSuccess()) {
			processAuthTokenResponse(token.toSuccessResponse().toJSONObject(), request, response,
					tokenParams.isRefresh());
		} else {
			if (token != null) {
				TokenErrorResponse errorResponse = token.toErrorResponse();
				ErrorObject errorObject = errorResponse.getErrorObject();
				if (errorObject != null && errorObject.getHTTPStatusCode() != 0) {
					if (errorObject.getDescription() != null) {
						response.sendError(errorObject.getHTTPStatusCode(), errorObject.getDescription());
					} else {
						response.sendError(errorObject.getHTTPStatusCode());
					}
				}
			}
		}
		return;

	}

	private void processAuthTokenResponse(JSONObject json, HttpServletRequest request, HttpServletResponse response,
			boolean setRefreshToken)
			throws IOException {
		JsonObjectBuilder object = Json.createObjectBuilder();
		JsonArrayBuilder arrBuilder = Json.createArrayBuilder();
		arrBuilder.add("rdap_level_0");
		arrBuilder.add("rdap_openidc_level_0");
		object.add("rdapConformance", arrBuilder);

		Encoder urlEncoder = Base64.getUrlEncoder();
		object.add("access_token",
				urlEncoder.encodeToString(json.getAsString("access_token").getBytes(StandardCharsets.UTF_8)));
		object.add("id_token",
				urlEncoder.encodeToString(json.getAsString("id_token").getBytes(StandardCharsets.UTF_8)));
		object.add("token_type", json.getAsString("token_type"));
		object.add("expires_in", json.getAsString("expires_in"));
		if (json.containsKey("refresh_token") && setRefreshToken) {
			object.add("refresh_token",
					urlEncoder.encodeToString(json.getAsString("refresh_token").getBytes(StandardCharsets.UTF_8)));
		}

		response.getWriter().print(object.build().toString());
	}



}
