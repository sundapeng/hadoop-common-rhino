/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.hadoop.security.tokenauth.jaas;

import java.util.List;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.tokenauth.token.Attribute;

public abstract class LoginModule implements 
    javax.security.auth.spi.LoginModule {
  
  public enum LOGIN_STATUS {
    LOGIN_SUCCESS,
    LOGIN_FAIL,
    LOGIN_NOTCOMPLETE
  };

  public enum LOGOUT_STATUS {
    LOGOUT_SUCCESS,
    LOGOUT_FAIL,
    LOGOUT_NOTCOMPLETE
  };
  
  private CallbackHandler callbackHandler;
  private AuthenticationContext authnContext;
  private int loginTries = 0;
  private boolean initFailed = false;
  private boolean loginHandled = false;
  private boolean logoutHandled = false;
  private boolean loginResult = true;
  private boolean logoutResult = true;
  
  @Override
  public void initialize(Subject subject, CallbackHandler callbackHandler,
      Map<String, ?> sharedState, Map<String, ?> options) {
    this.callbackHandler = callbackHandler;
    
    loginTries = 0;
    initFailed = false;
    loginHandled = false;
    logoutHandled = false;
    loginResult = true;
    logoutResult = true;
    
    AuthnContextCallback anthnContextCb = new AuthnContextCallback();
    try {
      callbackHandler.handle(new Callback[]{anthnContextCb});
    } catch (Exception e) {
      //login module initialize failed.
      initFailed = true;
    }
    
    authnContext = anthnContextCb.getAuthenticationContext();
    init(subject, sharedState, options);
  }
  
  @Override
  public boolean login() throws LoginException {
    authnContext.setHandlingModule(this);
    
    if(initFailed) {
      throw new LoginException("Login module init failed.");
    }
    
    if(loginHandled) {
      return loginResult;
    }
    
    Callback[] callbacks = getRequiredCallbacks();
    try {
      callbackHandler.handle(callbacks);
    } catch (Exception e) {
      throw new LoginException(e.getMessage());
    }
    LOGIN_STATUS status = loginImpl(callbacks);
    if(status == LOGIN_STATUS.LOGIN_FAIL){
      loginTries++; //login failed, increase tries
      if(getMaxTries() == -1 || loginTries < getMaxTries()) {
        throw new LoginFailedTryAgainException();
      } else {
        loginResult = false;
      }
    } else if(status == LOGIN_STATUS.LOGIN_NOTCOMPLETE) {
      throw new LoginNotCompletedException();
    } else if(status == LOGIN_STATUS.LOGIN_SUCCESS) {
      loginResult = true;
    }
    
    loginHandled = true;
    return loginResult;
  }
  
  @Override
  public boolean logout() throws LoginException {
    authnContext.setHandlingModule(this);
    
    if(logoutHandled) {
      return logoutResult;
    }
    
    LOGOUT_STATUS status = logoutImpl();
    if(status == LOGOUT_STATUS.LOGOUT_FAIL) {
      logoutResult = false;
    } else if(status == LOGOUT_STATUS.LOGOUT_NOTCOMPLETE) {
      throw new LogoutNotCompletedException();
    } else if(status == LOGOUT_STATUS.LOGOUT_SUCCESS) {
      logoutResult = true;
    }
    
    logoutHandled = true;
    return logoutResult;
  }
  
  @Override
  public boolean abort() throws LoginException {
    return true;
  }
  
  /**
   * Get configuration
   */
  protected Configuration getConf() {
    return authnContext.getConf();
  }
  
  /**
   * Get identity attributes
   */
  protected List<Attribute> getAttributes() {
    return authnContext.getAttributes();
  }
  
  protected AuthenticationContext getAuthnContext() {
    return authnContext;
  }
  
  protected abstract void init(Subject subject, 
      Map<String, ?> sharedState, Map<String, ?> options);
  
  protected int getMaxTries() {
    return -1;
  }
  
  protected abstract LOGIN_STATUS loginImpl(Callback[] callbacks) throws LoginException;
  
  protected abstract LOGOUT_STATUS logoutImpl() throws LoginException;
  
  public abstract String getModuleName();
  
  public abstract Callback[] getRequiredCallbacks();
}
