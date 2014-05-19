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
package org.apache.hadoop.security.tokenauth.cache.kerberos;

import java.io.IOException;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;

import org.apache.hadoop.security.tokenauth.kerberos.KerberosLoginConfiguration;
import org.apache.hadoop.security.tokenauth.kerberos.ServiceTicketGenerator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class KerberosLogin {
  public static final Log LOG = LogFactory.getLog(KerberosLogin.class);
  
  private String principal;
  private String keytab;

  public String getPrincipal() {
    return principal;
  }

  public void setPrincipal(String principal) {
    this.principal = principal;
  }

  public String getKeytab() {
    return keytab;
  }

  public void setKeytab(String keytab) {
    this.keytab = keytab;
  }

  public byte[] getServiceTicket(String servicePrincipal) throws IOException {
    Subject clientSubject = new Subject();
    LoginContext lc = null;
    byte[] serviceTicket = null;
    try { 
      if (principal == null || keytab == null) {
        lc = new LoginContext("user-kerberos", clientSubject, null,
            new KerberosLoginConfiguration());
        lc.login();
        principal = lc.getSubject().getPrincipals().iterator().next().getName();
        serviceTicket = Subject.doAs(clientSubject,
            new ServiceTicketGenerator(principal, servicePrincipal));
      } else {
        lc = new LoginContext("keytab-kerberos", clientSubject, null,
            new KerberosLoginConfiguration(keytab, principal));
        lc.login();
        serviceTicket = Subject.doAs(clientSubject,
            new ServiceTicketGenerator(principal, servicePrincipal));
      } 
    } catch (Exception e) {
      LOG.error(e.getMessage(),e);
      throw new IOException("getServiceTicket error.");
    }
    
    return serviceTicket;
  }
}
