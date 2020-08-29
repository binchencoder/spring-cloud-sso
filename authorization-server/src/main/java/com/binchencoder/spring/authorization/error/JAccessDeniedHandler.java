package com.binchencoder.spring.authorization.error;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

// handle 403 page
@Component
public class JAccessDeniedHandler implements AccessDeniedHandler {

  private static Logger LOGGER = LoggerFactory.getLogger(JAccessDeniedHandler.class);

  @Override
  public void handle(HttpServletRequest httpServletRequest,
      HttpServletResponse httpServletResponse,
      AccessDeniedException e) throws IOException, ServletException {

    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    if (auth != null) {
      LOGGER.info("User '" + auth.getName()
          + "' attempted to access the protected URL: "
          + httpServletRequest.getRequestURI());
    }

    httpServletResponse.sendRedirect(httpServletRequest.getContextPath() + "/403");
  }
}
