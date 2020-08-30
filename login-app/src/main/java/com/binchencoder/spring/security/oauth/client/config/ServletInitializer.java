/*
 * Copyright 2013-2014 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

package com.binchencoder.spring.security.oauth.client.config;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import org.springframework.util.ClassUtils;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;
import org.springframework.web.filter.CharacterEncodingFilter;
import org.springframework.web.filter.DelegatingFilterProxy;
import org.springframework.web.servlet.support.AbstractDispatcherServletInitializer;

/**
 * @author Jensen
 */
public class ServletInitializer extends AbstractDispatcherServletInitializer {

  @Override
  protected WebApplicationContext createServletApplicationContext() {
    AnnotationConfigWebApplicationContext context = new AnnotationConfigWebApplicationContext();
    context.scan(ClassUtils.getPackageName(getClass()));
    return context;
  }

  @Override
  protected String[] getServletMappings() {
    return new String[]{"/"};
  }

  @Override
  protected WebApplicationContext createRootApplicationContext() {
    return null;
  }

  @Override
  public void onStartup(ServletContext servletContext) throws ServletException {
    super.onStartup(servletContext);
    servletContext.getSessionCookieConfig().setPath("/");
    // 禁止 js 获取cookie
    servletContext.getSessionCookieConfig().setHttpOnly(true);
    // 只允许https 访问
    servletContext.getSessionCookieConfig().setSecure(true);

    // 增加prometheus
//    ServletRegistration.Dynamic dynamic = servletContext.addServlet("prometheus",
//        new io.prometheus.client.exporter.MetricsServlet());
//    dynamic.setLoadOnStartup(1);
//    dynamic.addMapping("/_/metrics");
//    DefaultExports.initialize();

    // 字符编码处理
    CharacterEncodingFilter characterEncodingFilter = new CharacterEncodingFilter();
    characterEncodingFilter.setEncoding("UTF-8");
    characterEncodingFilter.setForceEncoding(true);
    servletContext.addFilter("characterEncodingFilter", characterEncodingFilter)
        .addMappingForUrlPatterns(null, false, "/*");

    // 请求监控过滤器, 请求超过一定时间，打印警告日志
    DelegatingFilterProxy metricsFilter =
        new DelegatingFilterProxy(Configurations.REQUEST_STATUS_METRICS_FILTER_BEAN_NAME);
    metricsFilter
        .setContextAttribute("org.springframework.web.servlet.FrameworkServlet.CONTEXT.dispatcher");
    servletContext.addFilter(Configurations.REQUEST_STATUS_METRICS_FILTER_BEAN_NAME, metricsFilter)
        .addMappingForUrlPatterns(null, false, "/*");

    // localeFilter 语言参数解析 --> 放置在登录之后，可依据用户设置语言信息进行国际化展示
    DelegatingFilterProxy localeFilter = new DelegatingFilterProxy("localeFilter");
    localeFilter
        .setContextAttribute("org.springframework.web.servlet.FrameworkServlet.CONTEXT.dispatcher");
    servletContext.addFilter("localeFilter", localeFilter).addMappingForUrlPatterns(null, false,
        "/[^logout]");

    DelegatingFilterProxy filter = new DelegatingFilterProxy("springSecurityFilterChain");
    filter
        .setContextAttribute("org.springframework.web.servlet.FrameworkServlet.CONTEXT.dispatcher");
    servletContext.addFilter("springSecurityFilterChain", filter).addMappingForUrlPatterns(null,
        false, "/*");
  }

}
