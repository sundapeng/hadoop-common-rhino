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

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.tokenauth.has.HASConfiguration;
import org.apache.hadoop.security.tokenauth.token.Attribute;

import com.google.common.collect.Maps;

public class LoginImpl implements Login, AuthenticationContext{
  private Configuration conf;
  private Subject subject;
  private List<Attribute> attributes;
  private LoginContext loginContext;
  private LoginCallbackHandler loginCallbackHandler;
  private LoginModule handlingModule;
  private HttpServletRequest httpRequest;
  private HttpServletResponse httpResponse;
  private String failure;
  private Callback[] requiredCallbacks;
  private int loginStatus = -1;
  private int logoutStatus = -1;
  
  private static Map<String, Class<? extends LoginModule>> MODULES;
  private static Map<String, ?> BASIC_OPTIONS = Maps.newHashMap();
  
  public LoginImpl(Configuration conf) throws LoginException {
    this.conf = new Configuration(conf); //clone the configuration
    loginCallbackHandler = new LoginCallbackHandler(this);
    
    init();
  }
  
  public LoginImpl(Configuration conf, HttpServletRequest httpRequest, 
      HttpServletResponse httpResponse) throws LoginException {
    this(conf);
    this.httpRequest = httpRequest;
    this.httpResponse = httpResponse;
  }
  
  private void init() throws LoginException {
    try {
      subject = new Subject();
      loginContext = new LoginContext("jaas", subject, 
          loginCallbackHandler, getLoginConfiguration(conf));
    } catch (IOException e) {
      throw new LoginException("Jaas init failed");
    }
  }
  
  @Override
  public synchronized Subject getSubject() {
    return subject;
  }
  
  @Override
  public synchronized int login() {
    return login(null);
  }
  
  @Override
  public synchronized int login(Callback[] callbacks) {
    if (loginStatus == SUCCEED || loginStatus == FAILED) {
      throw new IllegalStateException("Login has finished.");
    }
    
    resetState();
    if(callbacks != null){
      loginCallbackHandler.setSubmittedCallbacks(callbacks);
    }
    
    try {
      loginContext.login();
    } catch (LoginNotCompletedException e) {
      //Break login to collect callbacks
      loginStatus = NOTCOMPLETED;
      requiredCallbacks = handlingModule.getRequiredCallbacks();
      return loginStatus;
    } catch (LoginFailedTryAgainException e) {
      //Allow user to enter his credentials again.
      loginStatus = RETRIED;
      failure = "login failed for " + handlingModule.getModuleName() + " and retry.";
      requiredCallbacks = handlingModule.getRequiredCallbacks();
      return loginStatus;
    } catch (LoginException e) {
      loginStatus = FAILED;
      failure = "login failed: " + e.getMessage();
      requiredCallbacks = handlingModule.getRequiredCallbacks();
      return loginStatus;
    }

    loginStatus = SUCCEED;
    return loginStatus;
  }
  
  @Override
  public synchronized int getLoginStatus() {
    return loginStatus;
  }
  
  @Override
  public synchronized int logout() {
    if (logoutStatus == SUCCEED || logoutStatus == FAILED) {
      throw new IllegalStateException("Logout has finished.");
    }
    
    resetState();
    
    try {
      loginContext.logout();
    } catch (LoginException e) {
      logoutStatus = FAILED;
      failure = "logout failed.";
      return logoutStatus;
    }
    
    logoutStatus = SUCCEED;
    return logoutStatus;
  }
  
  @Override
  public synchronized int getLogoutStatus() {
    return logoutStatus;
  }
  
  private void resetState() {
    failure = null;
    requiredCallbacks = null;
  }
  
  private static synchronized Class<? extends LoginModule> 
      getLoginModuleClass(String name) {
    if (MODULES == null) {
      MODULES = Maps.newHashMap();
      for(LoginModule module : ServiceLoader.load(LoginModule.class)) {
        MODULES.put(module.getModuleName(), module.getClass());
      }
    }
    
    Class<? extends LoginModule> mClass = MODULES.get(name);
    if (mClass == null) {
      return null;
    }
    
    return mClass;
  }
  
  private javax.security.auth.login.Configuration getLoginConfiguration(
      final Configuration conf) throws IOException {
    
    return new javax.security.auth.login.Configuration() {

      @Override
      public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
        
        String authnConf = conf.get(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_AUTHENTICATORS_KEY);
        
        List<AppConfigurationEntry> entries = 
            new ArrayList<AppConfigurationEntry>();
        if(authnConf != null) {
          String[] authenticators = authnConf.split(",");
          for(int i=0; i<authenticators.length; i++) {
            Class<? extends LoginModule> mClass = getLoginModuleClass(authenticators[i].trim());
            if(mClass == null) {
              throw new IllegalArgumentException("Can't find authentication module: " + authenticators[i]);
            }
            
            String controlFlag = conf.get(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_AUTHENTICATOR_PREFIX
                + authenticators[i] + HASConfiguration.HADOOP_SECURITY_TOKENAUTH_AUTHENTICATOR_CONTROLFLAG, "required");
            AppConfigurationEntry entry = new AppConfigurationEntry(mClass.getName()
                , getControlFlagFromStr(controlFlag), BASIC_OPTIONS);
            entries.add(entry);
          }
        }
        
        AppConfigurationEntry[] appEntries = new AppConfigurationEntry[entries.size()];
        return entries.toArray(appEntries);
      }
    };
  }
  
  /**
   * Get control flag for login module.
   */
  private LoginModuleControlFlag getControlFlagFromStr(String controlFlag) {
    if(controlFlag == null) {
      return null;
    } else if (controlFlag.equals("required")) {
      return LoginModuleControlFlag.REQUIRED;
    } else if (controlFlag.equals("requisite")) {
      return LoginModuleControlFlag.REQUISITE;
    } else if (controlFlag.equals("sufficient")) {
      return LoginModuleControlFlag.SUFFICIENT;
    } else if (controlFlag.equals("optional")) {
      return LoginModuleControlFlag.OPTIONAL;
    } else {
      throw new IllegalArgumentException("Invalid optional");
    }
  }

  @Override
  public synchronized void setHandlingModule(LoginModule module) {
    this.handlingModule = module;
  }

  @Override
  public synchronized Configuration getConf() {
    return conf;
  }

  @Override
  public synchronized List<Attribute> getAttributes() {
    if(attributes == null) {
      attributes = new ArrayList<Attribute>();
    }
    return attributes;
  }
  
  @Override
  public synchronized HttpServletRequest getHttpRequest() {
    return httpRequest;
  }
  
  @Override
  public synchronized HttpServletResponse getHttpResponse() {
    return httpResponse;
  }

  @Override
  public synchronized String getFailure() {
    return failure;
  }

  @Override
  public synchronized Callback[] getRequiredCallbacks() {
    return requiredCallbacks;
  }
}
