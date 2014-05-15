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

import java.io.IOException;
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.TextOutputCallback;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.apache.hadoop.security.HadoopKerberosName;
import org.apache.hadoop.security.tokenauth.has.HASConfiguration;
import org.apache.hadoop.security.tokenauth.jaas.LoginModule;
import org.apache.hadoop.security.tokenauth.kerberos.KerberosCallback;
import org.apache.hadoop.security.tokenauth.kerberos.KerberosLoginConfiguration;
import org.apache.hadoop.security.tokenauth.kerberos.ServiceTicketValidator;
import org.apache.hadoop.security.tokenauth.token.Attribute;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class KerberosLoginModule extends LoginModule {

  public static final Log LOG = LogFactory.getLog(KerberosLoginModule.class);

  static  {
    try {
      HadoopKerberosName.setConfiguration(new HASConfiguration());
    } catch (IOException e) {
      LOG.error("HadoopKerberosName init failed",e);
    }
  }

  private static final String NAME = "kerberos";

  private Subject subject;
  private Principal principal;

  private static KerberosAuthenticator rpcAuthenticator;
  private static KerberosAuthenticator httpAuthenticator;
  private static LdapConnector ldapConnector;

  @Override
  protected void init(Subject subject, Map<String, ?> sharedState,
                      Map<String, ?> options) {
    this.subject = subject;
    if (rpcAuthenticator == null) {
      synchronized (KerberosLoginModule.class) {
        if (rpcAuthenticator == null) {
          String keytab = getConf().get(HASConfiguration.
              HADOOP_SECURITY_TOKENAUTH_IDENTITY_SERVER_KEYTAB_KEY);
          LOG.info("Loading rpc keytab from conf:" + keytab);
          String krb5ServPrincipal = getConf().get(HASConfiguration.
              HADOOP_SECURITY_TOKENAUTH_IDENTITY_SERVER_PRINCIPAL_KEY);
          LOG.info("Loading rpc principal from conf:" + krb5ServPrincipal);
          rpcAuthenticator = new KerberosAuthenticator(keytab, krb5ServPrincipal);
        }
      }
    }
    if (httpAuthenticator == null) {
      synchronized (KerberosLoginModule.class) {
        if (httpAuthenticator == null) {
          String keytab = getConf().get(HASConfiguration.
              HADOOP_SECURITY_TOKENAUTH_IDENTITY_SERVER_HTTP_KEYTAB_KEY);
          LOG.info("Loading http keytab from conf:" + keytab);
          String httpPrincipal = getConf().get(HASConfiguration.
              HADOOP_SECURITY_TOKENAUTH_IDENTITY_SERVER_HTTP_PRINCIPAL_KEY);
          LOG.info("Loading http principal from conf:" + httpPrincipal);
          httpAuthenticator = new KerberosAuthenticator(keytab, httpPrincipal);
        }
      }
    }
    
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
    if (principal != null) {
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
  protected LOGIN_STATUS loginImpl(Callback[] callbacks) {
    KerberosCallback kerberosCallback = null;
    if (callbacks != null) {
      for (Callback callback : callbacks) {
        if (callback instanceof KerberosCallback) {
          kerberosCallback = (KerberosCallback) callback;
          break;
        }
      }
    }
    
    if (kerberosCallback == null) {
      return LOGIN_STATUS.LOGIN_NOTCOMPLETE;
    } else if (kerberosCallback.getTicket() == null) {
      LOG.error("Login failed",new LoginException("Service ticket is null"));
      return LOGIN_STATUS.LOGIN_FAIL;
    }

    try {
      String clientName = null;
      if(getAuthnContext().getHttpRequest() == null) {
        clientName = rpcAuthenticator.authenticate(kerberosCallback.getTicket());
      } else {
        clientName = httpAuthenticator.authenticate(kerberosCallback.getTicket());
      }
      
      this.principal = new KerberosPrincipal(clientName);
    } catch (LoginException e) {
      LOG.error("Login failed", e);
      return LOGIN_STATUS.LOGIN_FAIL;
    }

    return LOGIN_STATUS.LOGIN_SUCCESS;
  }

  @Override
  protected LOGOUT_STATUS logoutImpl() {
    subject.getPrincipals().remove(principal);
    getAttributes().clear();
    return LOGOUT_STATUS.LOGOUT_SUCCESS;
  }

  @Override
  public String getModuleName() {
    return NAME;
  }
  
  @Override
  protected int getMaxTries() {
    return 2;
  }

  @Override
  public Callback[] getRequiredCallbacks() {
    TextOutputCallback textOutputCb =
        new TextOutputCallback(TextOutputCallback.INFORMATION, "Kerberos");
    KerberosCallback kerberosCb = null;
    if (getAuthnContext().getHttpRequest() != null) {
      kerberosCb = new KerberosCallback(httpAuthenticator.getKrb5ServPrincipal());
    } else {
      kerberosCb = new KerberosCallback(rpcAuthenticator.getKrb5ServPrincipal());
    }
    
    return new Callback[]{textOutputCb, kerberosCb};
  }

  private static class KerberosAuthenticator {

    private String krb5ServPrincipalName;
    private Subject krb5ServSubject; 

    public KerberosAuthenticator(String keytab, String principal) {
      LOG.info("Create KerberosAuthenticator using keytab:" + keytab + " principal:" + principal);
      this.krb5ServPrincipalName = principal;
      
      krb5ServSubject = new Subject();
      LoginContext lc;
      try {
        lc = new LoginContext("keytab-kerberos", krb5ServSubject, null,
            new KerberosLoginConfiguration(keytab, krb5ServPrincipalName));

        lc.login();
      } catch (LoginException e) {
        throw new RuntimeException("Kerberos authenticate failed.");
      }
      
      krb5ServSubject = lc.getSubject();
    }

    public String authenticate(byte[] serviceTicket) throws LoginException {
      if (serviceTicket == null) {
        throw new NullPointerException();
      }
      LOG.info("Begin to authn service ticket length: " + serviceTicket.length);
      
      ServiceTicketValidator validator = new ServiceTicketValidator(serviceTicket, krb5ServPrincipalName);
      try {
        String clientName = Subject.doAs(krb5ServSubject, validator);
        return clientName;
      } catch (PrivilegedActionException e) {
        throw new LoginException("Service ticket is invalid: " + e.toString());
      }
    }

    public String getKrb5ServPrincipal() {
      return krb5ServPrincipalName;
    }
  }
}
