package com.binchencoder.spring.security.oauth.client.config;

import com.binchencoder.spring.security.oauth.client.handler.JAccessDeniedHandler;
import com.binchencoder.spring.security.oauth.client.handler.JAuthenticationEntryPoint;
import com.binchencoder.spring.security.oauth.client.route.Routes;
import com.binchencoder.spring.security.oauth.client.service.AuthenticationFailureCountingService;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthenticatedPrincipalOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.util.StringUtils;

@Configuration
public class Configurations {

  public static final String REQUEST_STATUS_METRICS_FILTER_BEAN_NAME = "requestStatusMetricsFilter";

//  @Bean
//  public OAuth2AuthorizedClientService authorizedClientService(
//      ClientRegistrationRepository clientRegistrationRepository) {
//    return new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository);
//  }
//
//  @Bean
//  public OAuth2AuthorizedClientRepository authorizedClientRepository(
//      OAuth2AuthorizedClientService authorizedClientService) {
//    return new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(authorizedClientService);
//  }

  /* 认证端点 & 认证失败处理器 */
  @Bean
  public JAuthenticationEntryPoint jAuthenticationEntryPoint() {
    return new JAuthenticationEntryPoint(new OrRequestMatcher(new AntPathRequestMatcher("/", "GET"),
        new AntPathRequestMatcher(Routes.OAUTH_AUTHORIZE, "GET")));
  }

  /* 认证拒绝处理器 */
  @Bean
  public JAccessDeniedHandler jAccessDeniedHandler() {
    return new JAccessDeniedHandler();
  }

  @Bean
  public AuthenticationFailureCountingService authenticationFailureCountingService() {
    return new AuthenticationFailureCountingService() {
      private String usernameParameter = "username";

      private String cacheKey(String username) {
        return "";
      }

      @Override
      public void resetAuthenticationFailure(HttpServletRequest request,
          HttpServletResponse response) {
        String username = request.getParameter(usernameParameter);
        if (!StringUtils.isEmpty(username)) {
          // 重置异常计数
        }
      }

      @Override
      public void increaseAuthenticationFailure(HttpServletRequest request,
          HttpServletResponse response) {
        String username = request.getParameter(usernameParameter);
        if (!StringUtils.isEmpty(username)) {
          // 增加异常计数
        }
      }

      @Override
      public int getAuthenticationFailure(HttpServletRequest request,
          HttpServletResponse response) {
        int countAccount = 0;
        String username = request.getParameter(usernameParameter);
        if (!StringUtils.isEmpty(username)) {

        }
        return countAccount;
      }

      @Override
      public boolean isNeedCheckIdentifyCode(HttpServletRequest request,
          HttpServletResponse response) {
        return getAuthenticationFailure(request, response) >= 5;
      }
    };
  }
}
