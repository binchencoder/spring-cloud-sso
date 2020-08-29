package com.binchencoder.spring.security.oauth.oauthorization.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;

// 授权服务器配置
@Configuration
@EnableAuthorizationServer // 开启授权服务
public class OAuth2AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

  @Autowired
  private PasswordEncoder passwordEncoder;

  @Override
  public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
//    clients
//        .jdbc(this.dataSource)
//        .passwordEncoder(PasswordEncoderFactories.createDelegatingPasswordEncoder());

//    clients.withClientDetails(clientDetailsService());

    clients
        .inMemory()
        .withClient("messaging-client")
        .secret(passwordEncoder.encode("secret")) // 客户端的密码(client_secret)，这里的密码应该是加密后的
        .authorizedGrantTypes("authorization_code", "client_credentials", "password")
        .scopes("message.read", "message.write")
        .redirectUris("http://localhost:8080/authorized")
        .and()
        .withClient("messaging-client1")
        .secret(passwordEncoder.encode("secret1"))
        .authorizedGrantTypes("client_credentials")
        .scopes("message.read", "message.write")
        .redirectUris("http://localhost:8080/authorized");
  }

  @Override
  public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
    super.configure(endpoints);
//    endpoints.authenticationManager()
  }

  @Override
  public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
    // 允许表单提交
    security.allowFormAuthenticationForClients()
        .checkTokenAccess("isAuthenticated()");
  }

//  @Bean
//  public ClientDetailsService clientDetailsService() {
//    return new JClientDetailsService();
//  }
}
