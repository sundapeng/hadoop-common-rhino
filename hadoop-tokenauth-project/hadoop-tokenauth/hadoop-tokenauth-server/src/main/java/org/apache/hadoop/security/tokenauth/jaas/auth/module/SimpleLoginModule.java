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

package org.apache.hadoop.security.tokenauth.jaas.auth.module;

import java.security.Principal;
import java.util.List;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.TextOutputCallback;
import javax.security.auth.login.LoginException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.security.Groups;
import org.apache.hadoop.security.tokenauth.jaas.LoginModule;
import org.apache.hadoop.security.tokenauth.token.Attribute;

public class SimpleLoginModule extends LoginModule {
  private static final Log LOG =  LogFactory.getLog(SimpleLoginModule.class);
  private static final String NAME = "simple";

  /**
   * SimplePrincipal is the user name
   */
  private static class SimplePrincipal implements Principal {
    private String name;
    
    public SimplePrincipal(String name) {
      this.name = name;
    }

    @Override
    public String getName() {
      return name;
    }
  }
  
  private Subject subject;
  private Principal principal;
  
  @Override
  protected void init(Subject subject, 
      Map<String, ?> sharedState, Map<String, ?> options) {
    this.subject = subject;
  }
  
  @Override
  public boolean commit() throws LoginException {
    if(principal != null) {
      subject.getPrincipals().add(principal);
      
      /* groups attribute */
      try {
        List<String> groups = Groups.getUserToGroupsMappingService(getConf()).getGroups(principal.getName());
        Attribute attribute = new Attribute("groups");
        if(groups != null) {
          for(String group : groups) {
            attribute.getValues().add(group);
          }
        }
        getAttributes().add(attribute);
      } catch (Exception e) {
        String error = "Can't get groups for " + principal.getName();
        LOG.warn(error);
        throw new LoginException(error);
      }

      return true;
    }
    return false;
  }

  @Override
  protected LOGIN_STATUS loginImpl(Callback[] callbacks) throws LoginException {
    String userName = null;
    if(callbacks != null) {
      for(int i=0; i<callbacks.length; i++) {
        Callback callback = callbacks[i];
        if(callback instanceof NameCallback) {
          userName = ((NameCallback)callback).getName();
        }
      }
    }
    
    if(userName == null) {
      return LOGIN_STATUS.LOGIN_NOTCOMPLETE;
    }
    
    principal = new SimplePrincipal(userName);
    
    return LOGIN_STATUS.LOGIN_SUCCESS;
  }

  @Override
  protected LOGOUT_STATUS logoutImpl() throws LoginException {
    return LOGOUT_STATUS.LOGOUT_SUCCESS;
  }
  
  @Override
  public String getModuleName() {
    return NAME;
  }

  @Override
  public Callback[] getRequiredCallbacks() {
    TextOutputCallback textOutputCb = new TextOutputCallback(
        TextOutputCallback.INFORMATION, "Simple Credentials");
    NameCallback nameCb = new NameCallback("Username");
    
    return new Callback[]{textOutputCb, nameCb};
  }
}
