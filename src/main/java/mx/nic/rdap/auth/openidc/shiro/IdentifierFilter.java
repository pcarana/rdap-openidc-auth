package mx.nic.rdap.auth.openidc.shiro;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.web.filter.authc.AuthenticatingFilter;

import mx.nic.rdap.auth.openidc.AuthenticationFlow;
import mx.nic.rdap.auth.openidc.Configuration;
import mx.nic.rdap.auth.openidc.OpenIDCProvider;
import mx.nic.rdap.auth.openidc.exception.ResponseException;
import mx.nic.rdap.auth.openidc.shiro.token.CustomOIDCToken;
import mx.nic.rdap.auth.openidc.shiro.token.UserInfoToken;

public class IdentifierFilter extends AuthenticatingFilter {

	public static final String ID_PARAM = "id";
	public static final String ID_TOKEN_PARAM = "id_token";
	public static final String ACCESS_TOKEN_PARAM = "access_token";

	@Override
	protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
		if (isValidParam(request, ID_PARAM)) {
			OpenIDCProvider provider = Configuration.getProvider();
			String userId = request.getParameter(ID_PARAM).trim();
			String location = AuthenticationFlow.getAuthenticationLocation(userId, request, provider);
			HttpServletResponse httpResponse = (HttpServletResponse) response;
			httpResponse.sendRedirect(location);
			return false;
		}
		return super.preHandle(request, response);
	}
	
	@Override
	protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) throws Exception {
		// TODO The issuer MAY be obtained from the referer, just to know where to validate tokens
		if (request.getAttribute(Configuration.USER_INFO_ATTR) != null) {
			return new UserInfoToken(request);
		}
		// FIXME The access_token also may be at the Authorization Header (value = "Bearer <the_code>"
		if (request.getParameter(ID_TOKEN_PARAM) != null && request.getParameter(ACCESS_TOKEN_PARAM) != null) {
			return new CustomOIDCToken(request.getParameter(ID_TOKEN_PARAM).trim(),
					request.getParameter(ACCESS_TOKEN_PARAM).trim());
		}
		return null;
	}
	
	@Override
	protected boolean isPermissive(Object mappedValue) {
		// The filter is permissive by default
		return true;
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
			httpResponse.setStatus(resp.getCode());
		} else {
			httpResponse.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
		}
		return false;
	}

}
