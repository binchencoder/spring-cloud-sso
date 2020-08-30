package com.binchencoder.spring.security.oauth.client.service;

import java.util.Collection;
import java.util.Collections;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

@SuppressWarnings("serial")
public class JUserDetails implements UserDetails {

  private long uid;
  private long cid;
  private boolean disable; // 帐号不可用
  private boolean locked; // 公司被停用
  private String password;
  private String alias; // 登录帐户名

  public JUserDetails() {
  }

  public JUserDetails(long uid, long cid, String password) {
    this.uid = uid;
    this.cid = cid;
    this.password = password;
  }

  public JUserDetails(long uid, long cid, String password, String alias) {
    this(uid, cid, password);
    this.alias = alias;
  }

  public void setUid(long uid) {
    this.uid = uid;
  }

  public void setCid(long cid) {
    this.cid = cid;
  }

  public void setPassword(String password) {
    this.password = password;
  }

  public long getUid() {
    return uid;
  }

  public long getCid() {
    return cid;
  }

  public String getJid() {
    return uid + "@" + cid;
  }

  public String getAlias() {
    return alias;
  }

  public void setAlias(String alias) {
    this.alias = alias;
  }

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return Collections.emptySet();
  }

  @Override
  public String getPassword() {
    return password;
  }

  @Override
  public String getUsername() {
    return String.valueOf(uid);
  }

  @Override
  public boolean isAccountNonExpired() {
    return true;
  }

  // 使用帐号锁定代表 公司被禁用
  @Override
  public boolean isAccountNonLocked() {
    return !locked;
  }

  @Override
  public boolean isCredentialsNonExpired() {
    return true;
  }

  // 使用帐号是否可用代表 用户是否可用
  @Override
  public boolean isEnabled() {
    return !disable;
  }

  public void setDisable(boolean disable) {
    this.disable = disable;
  }

  public void setLocked(boolean locked) {
    this.locked = locked;
  }

}
