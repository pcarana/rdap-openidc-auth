package mx.nic.rdap.auth.openidc.filter;

import java.io.IOException;
import java.net.URISyntaxException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.nimbusds.jose.util.Base64;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

import mx.nic.rdap.auth.openidc.AuthenticationFlow;
import mx.nic.rdap.auth.openidc.Configuration;
import mx.nic.rdap.auth.openidc.OpenIDCProvider;
import mx.nic.rdap.auth.openidc.exception.RequestException;
import mx.nic.rdap.auth.openidc.exception.ResponseException;
import mx.nic.rdap.auth.openidc.protocol.Discovery;

/**
 * Specific filter used to parse an authorization code sent by an OP, the
 * request MUST contain 2 parameters "state" and "code", any other parameter
 * will be ignored.
 *
 */
public class CodeFilter implements Filter {

	private static final String CODE_PARAM = "code";
	private static final String STATE_PARAM = "state";
	
	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
		//
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		// Get the request, the code and state MUST be present to forward the request
		String codeParam = request.getParameter(CODE_PARAM);
		String stateParam = request.getParameter(STATE_PARAM);
		if (codeParam == null || codeParam.isEmpty() || stateParam == null || stateParam.isEmpty()) {
			chain.doFilter(request, response);
			return;
		}
		String forwardURI = new Base64(stateParam).decodeToString();
		if (forwardURI == null || forwardURI.isEmpty()) {
			// Invalid state, continue chain
			chain.doFilter(request, response);
			return;
		}
		if (request instanceof HttpServletRequest) {
			HttpServletRequest httpRequest = (HttpServletRequest) request;
			// The code may had been requested from the tokens servlet
			if (forwardURI.startsWith("/tokens")) {
				forwardURI = updateQuery(forwardURI, httpRequest);
			} else {
				UserInfo userInfo = null;
				OpenIDCProvider provider;

				try {
					provider = Discovery.discoverProvider(getIdFromForwardURI(forwardURI));
					if (provider == null) {
						HttpServletResponse httpResponse = (HttpServletResponse) response;
						httpResponse.sendError(HttpServletResponse.SC_NOT_IMPLEMENTED, "OpenId Provider not supported");
						return;
					}
				} catch (URISyntaxException e) {
					HttpServletResponse httpResponse = (HttpServletResponse) response;
					httpResponse.sendError(HttpServletResponse.SC_BAD_REQUEST, e.getMessage());
					return;
				}

				
				try {
					userInfo = AuthenticationFlow.getUserInfoFromAuthCode(httpRequest.getQueryString(), provider);
				} catch (Exception e) {
					// Translate to HTTP Codes
					if (e instanceof ResponseException) {
						ResponseException responseExc = (ResponseException) e;
						HttpServletResponse httpResponse = (HttpServletResponse) response;
						httpResponse.sendError(responseExc.getCode(), responseExc.getMessage());
						return;
					} else if (e instanceof RequestException) {
						HttpServletResponse httpResponse = (HttpServletResponse) response;
						httpResponse.sendError(500, "Unexpected error, try again");
						return;
					}
					throw new ServletException(e);
				}
				request.setAttribute(Configuration.USER_INFO_ATTR, userInfo);
			}
			request.getRequestDispatcher(forwardURI).forward(request, response);
			return;
		}
		chain.doFilter(request, response);
	}

	private String getIdFromForwardURI(String forwardURI) {
		String idString = "id=";
		int idxOfIdKey = forwardURI.indexOf("?" + idString);
		if (idxOfIdKey < 0) {
			idxOfIdKey = forwardURI.indexOf("&" + idString);
			if (idxOfIdKey < 0) {
				return null;
			}
		}
		forwardURI = forwardURI.substring(idxOfIdKey + idString.length() + 1);
		if (forwardURI.indexOf("&") > 0) {
			forwardURI = forwardURI.substring(0, forwardURI.indexOf("&"));
		}
		return forwardURI;
	}

	private String updateQuery(String forwardURI, HttpServletRequest httpRequest) {
		String appendParams = httpRequest.getQueryString();
		return forwardURI.concat(forwardURI.contains("?") ? "&" : "?").concat(appendParams);
	}

	@Override
	public void destroy() { }

}
