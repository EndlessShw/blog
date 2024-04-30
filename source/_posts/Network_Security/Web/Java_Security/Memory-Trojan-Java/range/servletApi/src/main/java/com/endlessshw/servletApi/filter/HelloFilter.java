package com.endlessshw.servletApi.filter;

import javax.servlet.*;
import javax.servlet.annotation.WebFilter;
import java.io.IOException;

/**
 * @author hasee
 * @version 1.0
 * @description: TODO
 * @date 2023/5/4 20:49
 */
@WebFilter(urlPatterns = "/*")
public class HelloFilter implements Filter {
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        System.out.println("HelloFilter has been activated!");
        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {

    }
}
