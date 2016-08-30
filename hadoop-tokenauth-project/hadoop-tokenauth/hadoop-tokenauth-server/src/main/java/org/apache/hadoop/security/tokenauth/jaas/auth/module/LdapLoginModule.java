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
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.TextOutputCallback;
import javax.security.auth.login.LoginException;

import org.apache.hadoop.security.tokenauth.jaas.LoginModule;
import org.apache.hadoop.security.tokenauth.token.Attribute;

public class LdapLoginModule extends LoginModule {
  private static final String NAME = "ldap";
  
  /**
   * LdapPrincipal is the user name
   */
  private static class LdapPrincipal implements Principal {
    private String name;
    
    public LdapPrincipal(String name) {
      this.name = name;
    }

    @Override
    public String getName() {
      return name;
    }
  }
  
  private Subject subject;
  private Principal principal;
  private static LdapConnector ldapConnector;
  private DirContext dirContext;

  @Override
  protected void init(Subject subject, 
      Map<String, ?> sharedState, Map<String, ?> options) {
    this.subject = subject;
    
    if (ldapConnector == null) {
      synchronized (LdapLoginModule.class) {
        if (ldapConnector == null) {
          ldapConnector = new LdapConnector();
          ldapConnector.setConf(getConf());
        }
      }
    }
  }
  
  @Override
  public boolean commit() throws LoginException {
    if(principal != null) {
      subject.getPrincipals().add(principal);

      List<String> groups = new ArrayList<String>();
      List<Attribute> attributes = getAttributes();
      ldapConnector.query(principal.getName(), groups, attributes);
      if (groups != null) {
        Attribute groupsAttr = new Attribute(Attribute.GROUPS);
        groupsAttr.getValues().addAll(groups);
        attributes.add(groupsAttr);
      }
      
      return true;
    }
    return false;
  }
  
  @Override
  protected LOGIN_STATUS loginImpl(Callback[] callbacks) throws LoginException {
    String ldapUser = null;
    String ldapPassword = null;
    if(callbacks != null) {
      for(int i=0; i<callbacks.length; i++) {
        Callback callback = callbacks[i];
        if(callback instanceof NameCallback) {
          ldapUser = ((NameCallback)callback).getName();
        } else if (callback instanceof PasswordCallback) {
          char[] password = ((PasswordCallback)callback).getPassword();
          if(password != null) {
            ldapPassword = new String(password);
          }
        }
      }
    }
    
    if(ldapUser == null || ldapPassword == null) {
      return LOGIN_STATUS.LOGIN_NOTCOMPLETE;
    }
    
    dirContext = ldapConnector.authenticate(ldapUser, ldapPassword);
    if(dirContext != null) {
      principal = new LdapPrincipal(ldapUser);
    } else {
      return LOGIN_STATUS.LOGIN_FAIL;
    }

    return LOGIN_STATUS.LOGIN_SUCCESS;
  }

  @Override
  protected LOGOUT_STATUS logoutImpl() throws LoginException {
    subject.getPrincipals().remove(principal);
    getAttributes().clear();
    try {
      dirContext.close();
    } catch (NamingException e) {
    }
    
    return LOGOUT_STATUS.LOGOUT_SUCCESS;
  }

  @Override
  public String getModuleName() {
    return NAME;
  }
  
  @Override
  protected int getMaxTries() {
    //ldap allows user to try.
    return -1;
  }

  @Override
  public Callback[] getRequiredCallbacks() {
    TextOutputCallback textOutputCb = new TextOutputCallback(
        TextOutputCallback.INFORMATION, "LDAP Credentials");
    NameCallback nameCb = new NameCallback("Username");
    PasswordCallback pwdCb = new PasswordCallback("Password", false);
    
    return new Callback[]{textOutputCb, nameCb, pwdCb};
  }
}
