package com.binchencoder.spring.security.oauth.authorization.service;

import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;

public class JClientDetailsService implements ClientDetailsService {

  @Override
  public ClientDetails loadClientByClientId(String clientId) throws ClientRegistrationException {
    return null;
  }
}
