package com.vmware.bdd.security;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

public class RedirectFailureHandler implements AuthenticationFailureHandler {
   private static final Logger logger = Logger.getLogger(RedirectFailureHandler.class);
   public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
         AuthenticationException exception) throws IOException, ServletException {

      logger.debug("sending 401 Unauthorized error");
      response.sendRedirect("/serengeti?LoginErrMsg=SSOTokenAuthenticationError");
   }
}
