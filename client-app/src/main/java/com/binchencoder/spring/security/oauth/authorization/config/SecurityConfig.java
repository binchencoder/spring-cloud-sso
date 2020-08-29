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
package com.binchencoder.spring.security.oauth.authorization.config;

import com.binchencoder.spring.security.oauth.authorization.authentication.JUserNamePasswordAuthenticationProvider;
import com.binchencoder.spring.security.oauth.authorization.service.JUserDetailsService;
import java.util.ArrayList;
import java.util.List;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * @author binchencoder
 */
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

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
    http
        .authorizeRequests()
        .anyRequest().authenticated()
        .and()
        .formLogin()
        .loginPage("/login")
        .failureUrl("/login-error")
        .permitAll()
        .and()
        .oauth2Client();
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
}
