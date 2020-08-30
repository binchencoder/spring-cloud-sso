package com.binchencoder.spring.security.oauth.client.handler;

import com.binchencoder.spring.security.oauth.client.route.Routes;
import com.binchencoder.spring.security.oauth.client.service.JUserDetails;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

public class JForwardAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

  private static final Logger LOGGER =
      LoggerFactory.getLogger(JForwardAuthenticationSuccessHandler.class);
  private String targetUrl = Routes.OAUTH_SUCCESS;
//  private KafkaStorageAdapter kafkaStorageAdapter;

//  public void setKafkaStorageAdapter(KafkaStorageAdapter kafkaStorageAdapter) {
//    this.kafkaStorageAdapter = kafkaStorageAdapter;
//  }

  public void setTargetUrl(String targetUrl) {
    this.targetUrl = targetUrl;
  }

  @Override
  public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
      Authentication authentication) throws IOException, ServletException {
    RequestDispatcher dispatcher = request.getRequestDispatcher(targetUrl);
    dispatcher.forward(request, response);

    if (authentication.getPrincipal() instanceof JUserDetails) {
      JUserDetails details = (JUserDetails) authentication.getPrincipal();
      try {
        sendKafkaMessage(request, details.getUserID(), details.getCompanyID());
      } catch (Exception e) {
        LOGGER.error("Notify uid:" + details.getUserID() + ", cid:" + details.getCompanyID()
            + " login success to DataCenter Fail.", e);
      }
    }
  }

  private void sendKafkaMessage(HttpServletRequest request, long uid, long cid) {
    SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMddHHmmssSSSZ");
    String dateStr = sdf.format(new Date());
    String ip = getRemoteIpNginx(request);
    String userAgent = request.getHeader(Routes.USER_AGENT);
    userAgent = StringUtils.isNotBlank(userAgent) ? userAgent.trim() : "";

    String messages = dateStr + "|" + cid + "|" + uid + "|" + ip + "|" + userAgent;
    LOGGER.debug("messages:{}", messages);

//    kafkaStorageAdapter.sendKafkaMessage(Logtopic.MGTLOGIN, messages);
  }

  private String getRemoteIpNginx(HttpServletRequest request) {
    String ip = request.getHeader("X-Forwarded-For");
    if (ip != null && ip.contains(",")) {
      ip = ip.split(",")[0];
    }
    if (ip == null || ip.length() == 0) {
      ip = request.getHeader("X-Real-IP");
    }
    if (ip == null || ip.length() == 0) {
      ip = request.getRemoteAddr();
    }
    return ip;
  }
}
