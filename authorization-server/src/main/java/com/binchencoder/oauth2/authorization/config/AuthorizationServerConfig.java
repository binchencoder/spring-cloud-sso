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
package com.binchencoder.oauth2.authorization.config;

import com.binchencoder.oauth2.authorization.authentication.JUserNamePasswordAuthenticationProvider;
import com.binchencoder.oauth2.authorization.service.JUserDetailsService;
import java.util.UUID;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.keys.KeyManager;
import org.springframework.security.crypto.keys.StaticKeyGeneratingKeyManager;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

/**
 * @author binchencoder
 */
@EnableWebSecurity
@Import(OAuth2AuthorizationServerConfiguration.class)
public class AuthorizationServerConfig {

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

  @Bean
  public UserDetailsService userDetailsService() {
    return new JUserDetailsService();
  }
}