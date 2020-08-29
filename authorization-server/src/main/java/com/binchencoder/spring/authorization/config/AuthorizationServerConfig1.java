/*
 * Copyright 2020 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.binchencoder.spring.authorization.config;

import com.binchencoder.spring.authorization.authentication.JUserNamePasswordAuthenticationProvider;
import com.binchencoder.spring.authorization.service.JUserDetailsService;
import java.util.UUID;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.keys.KeyManager;
import org.springframework.security.crypto.keys.StaticKeyGeneratingKeyManager;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.web.OAuth2TokenEndpointFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * @author binchencoder
 */
//@EnableWebSecurity
public class AuthorizationServerConfig1 extends WebSecurityConfigurerAdapter {

  @Override
  public void configure(WebSecurity web) {
    web
        .ignoring()
        .antMatchers("/webjars/**");
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer =
        new OAuth2AuthorizationServerConfigurer<>();

    http
        .requestMatcher(new OrRequestMatcher(authorizationServerConfigurer.getEndpointMatchers()))
        .authorizeRequests(authorizeRequests ->
            authorizeRequests
                .anyRequest().authenticated()
        )
        .formLogin()
        .loginPage("/login")
        .failureUrl("/login-error")
        .permitAll()
        .and()
        .csrf(csrf -> csrf.ignoringRequestMatchers(tokenEndpointMatcher()))
        .apply(authorizationServerConfigurer);
  }

  private static RequestMatcher tokenEndpointMatcher() {
    return new AntPathRequestMatcher(
        OAuth2TokenEndpointFilter.DEFAULT_TOKEN_ENDPOINT_URI,
        HttpMethod.POST.name());
  }

  // @formatter:off
  @Bean
  public RegisteredClientRepository registeredClientRepository() {
//    Set<String> redirectUris = new HashSet<>(2);
//    redirectUris.add("http://localhost:8080");
//    redirectUris.add("http://localhost:8080/authorized");

    RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
        .clientId("messaging-client")
        .clientSecret("secret")
        .clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
        .authorizationGrantType(AuthorizationGrantType.PASSWORD)
        .redirectUri("http://localhost:8080/authorized")
//        .redirectUris(uris -> uris.addAll(redirectUris))
        .scope("message.read")
        .scope("message.write")
        .build();
    return new InMemoryRegisteredClientRepository(registeredClient);
  }
  // @formatter:on

  @Bean
  public KeyManager keyManager() {
    return new StaticKeyGeneratingKeyManager();
  }

  @Bean
  public AuthenticationProvider authenticationProvider() {
    AuthenticationProvider authenticationProvider = new JUserNamePasswordAuthenticationProvider(
        userDetailsService());
    return authenticationProvider;
  }

  // @formatter:off
  @Bean
  public UserDetailsService userDetailsService() {
    return new JUserDetailsService();
  }
  // @formatter:on
}