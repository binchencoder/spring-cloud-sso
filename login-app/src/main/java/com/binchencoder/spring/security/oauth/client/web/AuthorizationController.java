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
package com.binchencoder.spring.security.oauth.client.web;

import static org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient;

import com.binchencoder.spring.security.oauth.client.exception.AnotherUserLoginedAccessDeniedException;
import com.binchencoder.spring.security.oauth.client.route.Routes;
import com.binchencoder.spring.security.oauth.client.service.AuthenticationFailureCountingService;
import com.binchencoder.spring.security.oauth.client.service.JUserDetails;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import java.awt.Color;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.regex.Pattern;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.WebAttributes;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * @author binchencoder
 */
@Controller
public class AuthorizationController {

  private static final Logger LOGGER = LoggerFactory.getLogger(AuthorizationController.class);

  private static final Pattern mobilePattern = Pattern.compile("\\d+");
  private static final String ALIAS = "alias";
  private static final String ID = "id";
  private static final Map<Class<? extends Exception>, String> exceptionMap = new HashMap<>();

  @Value("${messages.base-uri}")
  private String messagesBaseUri;

  @Autowired
  private AuthenticationFailureCountingService authenticationFailureCountingService;

  @Autowired
  private OAuth2AuthorizedClientService authorizedClientService;

  @Autowired
  private WebClient webClient;

  @RequestMapping({Routes.OAUTH_LOGIN, Routes.OAUTH_FAILURE_HTML})
  public String getOAuthLogin(HttpServletRequest request, HttpServletResponse response,
      @RequestParam(required = false) String display,
      @RequestParam(required = false) String client_id,
      @RequestParam(required = false, defaultValue = "0") long uid,
      @RequestParam(required = false) String redirect_uri, Model model) {
    if (!"relogin".equals(display) && !"mobile".equals(display) && !"dialog".equals(display)
        && !"sns".equals(display) && !"college".equals(display)) {
      display = "default";
    }
    if ("college".equals(display)) {
      model.addAttribute("collegeRegisterUrl",
          redirect_uri.substring(0, redirect_uri.indexOf("security")) + "security/register");
    }
    model.addAttribute("showIdentifyCode",
        authenticationFailureCountingService.isNeedCheckIdentifyCode(request, response));
    if (uid != 0) {
      model.addAttribute("uid", uid);
    }

    AuthenticationException exception =
        (AuthenticationException) request.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
    String errorMsg = getErrorMsg(exception);
    if (errorMsg != null) {
      model.addAttribute("error", errorMsg);
    }

//    return Routes.LOGIN_URL + display;
    return Routes.LOGIN_URL;
  }

  @RequestMapping(Routes.OAUTH_FAILURE)
  @ResponseBody
  public Map<String, Object> getOAuthFailure(HttpServletRequest request,
      HttpServletResponse response) {
    Map<String, Object> ret = new HashMap<>();
    // 登录名记忆
    String username = request.getParameter("username");
    if (username != null && !username.isEmpty()
        && (username.contains("@") || mobilePattern.matcher(username).matches())) { // 包含 @
      // 符号的登录名才进行记忆
      ret.put("username", username);
    }

    ret.put("showIdentifyCode",
        authenticationFailureCountingService.isNeedCheckIdentifyCode(request, response));

    AuthenticationException exception =
        (AuthenticationException) request.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
    String errorMsg = getErrorMsg(exception);
    if (errorMsg != null) {
      ret.put("error", errorMsg);
    } else {
      LOGGER.warn("未捕获的授权异常", exception);
      ret.put("error", "UnknownException");
    }
    return ret;
  }

  @RequestMapping(Routes.OAUTH_DENIED_NOTREQUIREDUSER)
  @ResponseBody
  public Map<String, Object> getOAuthDeniedNotRequiredUser(HttpServletRequest request,
      HttpServletResponse response) {
    Map<String, Object> ret = new HashMap<>();
    // 登录名记忆
    String username = request.getParameter("username");
    if (username != null && !username.isEmpty()
        && (username.contains("@") || mobilePattern.matcher(username).matches())) { // 包含 @
      // 符号的登录名才进行记忆
      ret.put("username", username);
    }

    ret.put("showIdentifyCode",
        authenticationFailureCountingService.isNeedCheckIdentifyCode(request, response));
    // NotRequiredUserAccessDeniedException exception = (NotRequiredUserAccessDeniedException)
    // request.getAttribute(WebAttributes.ACCESS_DENIED_403);
    ret.put("error", "NotRequiredUser");
    return ret;
  }

  @RequestMapping(Routes.OAUTH_DENIED_UNMATCHUSER)
  @ResponseBody
  public Map<String, Object> getOAuthDeniedUnMatchUser(HttpServletRequest request) {
    Map<String, Object> ret = new HashMap<>();

    AnotherUserLoginedAccessDeniedException ex = (AnotherUserLoginedAccessDeniedException) request
        .getAttribute(WebAttributes.ACCESS_DENIED_403);
    if (ex == null) {
      return ret;
    }

    Map<String, Serializable> pre_user =
        getAliasAndId((UserDetails) ex.getExistingAuth().getPrincipal());
    Map<String, Serializable> current_user =
        getAliasAndId((UserDetails) ex.getAuth().getPrincipal());

    ret.put("currUser", current_user.get(ALIAS));
    ret.put("preUser", pre_user.get(ALIAS));

//    try {
//      ret.put("token",
//          tokenService.allocateToken((Serializable) current_user.get(ALIAS), 2 * 60 * 60));
//    } catch (Exception e) {
//      LOGGER.error("访问Token Service 异常", e);
//    }
    ret.put("error", "UnmatchUser");
    return ret;
  }

  @GetMapping("/authorized")    // registered redirect_uri for authorization_code
  public String authorized(Model model,
      @RegisteredOAuth2AuthorizedClient("messaging-client-auth-code") OAuth2AuthorizedClient authorizedClient,
      @AuthenticationPrincipal OAuth2User oauth2User) {
    String[] messages = retrieveMessages(authorizedClient);
    model.addAttribute("messages", messages);
    return "index";
  }

  @GetMapping(value = "/authorize", params = "grant_type=authorization_code")
  public String authorization_code_grant(Model model,
      @RegisteredOAuth2AuthorizedClient("messaging-client-auth-code") OAuth2AuthorizedClient authorizedClient) {
    String[] messages = retrieveMessages(authorizedClient);
    model.addAttribute("messages", messages);
    return "index";
  }

  @GetMapping(value = "/authorize", params = "grant_type=client_credentials")
  public String client_credentials_grant(Model model,
      @RegisteredOAuth2AuthorizedClient("messaging-client-client-creds") OAuth2AuthorizedClient authorizedClient) {
    String[] messages = retrieveMessages(authorizedClient);
    model.addAttribute("messages", messages);
    return "index";
  }

  @PostMapping(value = "/authorize", params = "grant_type=password")
  public String password_grant(Model model,
      @RegisteredOAuth2AuthorizedClient("messaging-client-password") OAuth2AuthorizedClient authorizedClient) {
    String[] messages = retrieveMessages(authorizedClient);
    model.addAttribute("messages", messages);
    return "index";
  }

  private String[] retrieveMessages(OAuth2AuthorizedClient authorizedClient) {
    return this.webClient
        .get()
        .uri(this.messagesBaseUri)
//        .attributes(clientRegistrationId(clientRegistrationId))
        .attributes(oauth2AuthorizedClient(authorizedClient))
        .retrieve()
        .bodyToMono(String[].class)
        .block();
  }

  /**
   * 根据exception获取对应的错误描述
   */
  protected String getErrorMsg(Exception exception) {
    if (exception == null) {
      return null;
    }
    return exceptionMap.get(exception.getClass());
  }

  private Color getRandColor(Random random, int fc, int bc) {
    if (fc > 255) {
      fc = 255;
    }
    if (bc > 255) {
      bc = 255;
    }
    int r = fc + random.nextInt(bc - fc);
    int g = fc + random.nextInt(bc - fc);
    int b = fc + random.nextInt(bc - fc);
    return new Color(r, g, b);
  }

  private Map<String, Serializable> getAliasAndId(UserDetails userDetails) {
    Map<String, Serializable> map = new HashMap<>();
    if (userDetails instanceof JUserDetails) {
      JUserDetails details = (JUserDetails) userDetails;

      long id = details.getUserID();
      String alias = details.getAlias();
      if (StringUtils.isBlank(alias)) {
//        User user = userService.getUserById(id);
//        if (user != null) {
//          Company company = companyService.getCompanyById(user.getCompanyId());
//          if (company != null) {
//            alias = user.getLoginName() + AuthnService.SPLIT + company.getCode();
//          } else {
//            alias = String.valueOf(id);
//          }
      } else {
        alias = String.valueOf(id);
      }

      map.put(ID, id);
      map.put(ALIAS, alias);

      return map;
    }

    return map;
  }
}