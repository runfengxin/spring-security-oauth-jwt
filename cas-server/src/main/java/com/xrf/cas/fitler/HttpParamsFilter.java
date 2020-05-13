package com.xrf.cas.fitler;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

public class HttpParamsFilter implements Filter {
    public String REQUESTED_URL = "CasRequestedUrl";

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain)
            throws IOException, ServletException {
        final HttpServletRequest request = (HttpServletRequest) servletRequest;
        final HttpServletResponse response = (HttpServletResponse) servletResponse;
        HttpSession session = request.getSession();

        String requestPath = WebUtils.getFullPath(request);

        session.setAttribute(REQUESTED_URL, requestPath);

        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {

    }
}
