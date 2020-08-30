/*
 * Copyright 2012-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.binchencoder.spring.security.oauth.client.config;

import com.binchencoder.spring.security.oauth.client.authentication.JUserNamePasswordAuthenticationProvider;
import com.binchencoder.spring.security.oauth.client.filter.JAuthenticationServiceExceptionFilter;
import com.binchencoder.spring.security.oauth.client.filter.JLogoutRecordFilter;
import com.binchencoder.spring.security.oauth.client.filter.JRequiredUserCheckFilter;
import com.binchencoder.spring.security.oauth.client.filter.JUidCidTokenAuthenticationFilter;
import com.binchencoder.spring.security.oauth.client.filter.JUsernamePasswordAuthenticationFilter;
import com.binchencoder.spring.security.oauth.client.handler.JAccessDeniedHandler;
import com.binchencoder.spring.security.oauth.client.handler.JAccessTokenResponseConverter;
import com.binchencoder.spring.security.oauth.client.handler.JAuthenticationEntryPoint;
import com.binchencoder.spring.security.oauth.client.handler.JAuthorizationRequestResolver;
import com.binchencoder.spring.security.oauth.client.handler.JForwardAuthenticationSuccessHandler;
import com.binchencoder.spring.security.oauth.client.matcher.JUidCidTokenRequestMatcher;
import com.binchencoder.spring.security.oauth.client.route.Routes;
import com.binchencoder.spring.security.oauth.client.service.AuthenticationFailureCountingService;
import com.binchencoder.spring.security.oauth.client.service.JUserDetailsService;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.servlet.http.Cookie;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.session.CompositeSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.client.RestTemplate;

/**
 * @author binchencoder
 */
@EnableWebSecurity
public class OAuth2ClientSecurityConfig extends WebSecurityConfigurerAdapter {

  @Autowired
  private ClientRegistrationRepository clientRegistrationRepository;

  @Autowired
  private JAuthenticationEntryPoint jAuthenticationEntryPoint;

  @Autowired
  private JAccessDeniedHandler jAccessDeniedHandler;

  @Autowired
  private AuthenticationFailureCountingService authenticationFailureCountingService;

  @Override
  public UserDetailsService userDetailsServiceBean() throws Exception {
    return userDetailsService();
  }

  @Override
  public AuthenticationManager authenticationManagerBean() throws Exception {
    List<AuthenticationProvider> providers = new ArrayList<>();
    providers.add(authenticationProvider());

    return new ProviderManager(providers);
  }

  @Override
  public void configure(WebSecurity web) {
    web
        .ignoring()
        .antMatchers("/webjars/**");
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    List<SessionAuthenticationStrategy> sessionStrategies = new ArrayList<>(1);
    sessionStrategies.add((authentication, request, response) -> {
      String accessToken = authentication.getCredentials().toString();
//        Cookie cookie =
//            AccessTokenRepresentSecurityContextRepository.getOrNewAccessTokenCookie(request);
      Cookie cookie = new Cookie("", "");
      String saveInfo = request.getParameter("saveinfo");
      boolean persist =
          StringUtils.isNotBlank(saveInfo) && !"false".equalsIgnoreCase(saveInfo.trim());
      if (!cookie.getValue().equals(accessToken) || persist) {
        cookie.setValue(accessToken);
        if (persist) {
          cookie.setMaxAge(30 * 24 * 60 * 60);
        }

        response.addCookie(cookie);
      }
    });

    JUsernamePasswordAuthenticationFilter jUsernamePasswordAuthenticationFilter =
        getJUsernamePasswordAuthenticationFilter(sessionStrategies);

    // @formatter:off
    http
        .authorizeRequests()
        .antMatchers(Routes.DEFAULT, Routes.LOGIN).permitAll()
        .anyRequest().authenticated()
        .and()
        .formLogin()
//        .loginPage("/login")
//        .failureUrl("/login-error")
        .permitAll()
        .and()
        .oauth2Login()
        .authorizationEndpoint()
        .authorizationRequestResolver(jAuthorizationRequestResolver())
        .and()
        .and()
        .exceptionHandling() // 3. -> 安全异常处理 LogoutFilter 之后，确保所有登录异常纳入异常处理
        .authenticationEntryPoint(jAuthenticationEntryPoint)
        .accessDeniedHandler(jAccessDeniedHandler)
        .and()
        .oauth2Client()
        .and()
        // 认证服务内部异常处理
        .addFilterBefore(getJAuthenticationServiceExceptionFilter(),
            ExceptionTranslationFilter.class)
        // 已经登录帐号冲突检测
        .addFilterAfter(getJRequiredUserCheckFilter(), ExceptionTranslationFilter.class)
        // 账号登陆记录
        .addFilterAfter(getJLogoutRecordFilter(), getJRequiredUserCheckFilter().getClass())
        // 表单登录 --> 使可以被异常捕获
        .addFilterAfter(jUsernamePasswordAuthenticationFilter,
            getJLogoutRecordFilter().getClass())
        // 一键登录 --> 使可以被异常捕获
        .addFilterAfter(getJUidCidTokenAuthenticationFilter(sessionStrategies),
            jUsernamePasswordAuthenticationFilter.getClass());

    http.csrf().disable(); // 关跨域保护
    http.headers().frameOptions().disable();
    // @formatter:on
  }

  @Bean
  public AuthenticationProvider authenticationProvider() {
    AuthenticationProvider authenticationProvider = new JUserNamePasswordAuthenticationProvider(
        userDetailsService());
    return authenticationProvider;
  }

  @Bean
  public UserDetailsService userDetailsService() {
    // Load user details in memory
//    UserDetails user = User.withDefaultPasswordEncoder()
//        .username("user1")
//        .password("password")
//        .roles("USER")
//        .build();
//    return new InMemoryUserDetailsManager(user);

    return new JUserDetailsService();
  }

  private OAuth2AuthorizationRequestResolver jAuthorizationRequestResolver() {
    return new JAuthorizationRequestResolver(this.clientRegistrationRepository);
  }

  private OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> jAccessTokenResponseClient() {
    OAuth2AccessTokenResponseHttpMessageConverter tokenResponseHttpMessageConverter =
        new OAuth2AccessTokenResponseHttpMessageConverter();
    tokenResponseHttpMessageConverter
        .setTokenResponseConverter(new JAccessTokenResponseConverter());

    RestTemplate restTemplate = new RestTemplate(Arrays.asList(
        new FormHttpMessageConverter(), tokenResponseHttpMessageConverter));
    restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());

    DefaultAuthorizationCodeTokenResponseClient tokenResponseClient = new DefaultAuthorizationCodeTokenResponseClient();
    tokenResponseClient.setRestOperations(restTemplate);

    return tokenResponseClient;
  }

  // 表单登录
  private JUsernamePasswordAuthenticationFilter getJUsernamePasswordAuthenticationFilter(
      List<SessionAuthenticationStrategy> sessionStrategies) throws Exception {
    JUsernamePasswordAuthenticationFilter formLogin = new JUsernamePasswordAuthenticationFilter();
    JForwardAuthenticationSuccessHandler jForwardAuthenticationSuccessHandler =
        new JForwardAuthenticationSuccessHandler();
//    jForwardAuthenticationSuccessHandler.setKafkaStorageAdapter(kafkaStorageAdapter);
    formLogin.setAuthenticationSuccessHandler(jForwardAuthenticationSuccessHandler);
    formLogin.setAuthenticationFailureCountingService(authenticationFailureCountingService);
    formLogin.setRequiresAuthenticationRequestMatcher(new OrRequestMatcher(
        new AntPathRequestMatcher(Routes.DEFAULT, RequestMethod.POST.toString()),
        new AntPathRequestMatcher(Routes.OAUTH_AUTHORIZE, RequestMethod.POST.toString())));
    formLogin.setAuthenticationManager(authenticationManagerBean());
    formLogin.setUsernameParameter(OAuth2ParameterNames.USERNAME);
    formLogin.setPasswordParameter(OAuth2ParameterNames.PASSWORD);
    formLogin.setAuthenticationFailureHandler(jAuthenticationEntryPoint);
    formLogin.setSessionAuthenticationStrategy(
        new CompositeSessionAuthenticationStrategy(sessionStrategies));
    return formLogin;
  }

  // 退出登录记录生成器
  private JLogoutRecordFilter getJLogoutRecordFilter() {
    return new JLogoutRecordFilter(
        new AntPathRequestMatcher(Routes.OAUTH_AUTHORIZE, RequestMethod.GET.toString()));
  }

  // 一键登录
  private JUidCidTokenAuthenticationFilter getJUidCidTokenAuthenticationFilter(
      List<SessionAuthenticationStrategy> sessionStrategies) throws Exception {
    JUidCidTokenAuthenticationFilter jtokenLogin = new JUidCidTokenAuthenticationFilter();
    jtokenLogin.setAuthenticationManager(authenticationManagerBean());
    jtokenLogin.setAuthenticationFailureHandler(jAuthenticationEntryPoint);
    jtokenLogin.setSessionAuthenticationStrategy(
        new CompositeSessionAuthenticationStrategy(sessionStrategies));
    return jtokenLogin;
  }

  private JAuthenticationServiceExceptionFilter getJAuthenticationServiceExceptionFilter() {
    JAuthenticationServiceExceptionFilter serviceExceptionFilter =
        new JAuthenticationServiceExceptionFilter();
    serviceExceptionFilter.setAuthenticationEntryPoint(jAuthenticationEntryPoint);
    return serviceExceptionFilter;
  }

  private JRequiredUserCheckFilter getJRequiredUserCheckFilter() {
    return new JRequiredUserCheckFilter(new AndRequestMatcher(
        new OrRequestMatcher(
            new AntPathRequestMatcher(Routes.DEFAULT, RequestMethod.GET.toString()),
            new AntPathRequestMatcher(Routes.OAUTH_AUTHORIZE, RequestMethod.GET.toString())),
        new NegatedRequestMatcher(new JUidCidTokenRequestMatcher(Routes.OAUTH_AUTHORIZE))));
  }
}
