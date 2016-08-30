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
package org.apache.hadoop.security.tokenauth.kerberos;

import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

public class ServiceTicketValidator implements PrivilegedExceptionAction<String> {
  protected byte[] serviceTicket;
  private String principal;

  public ServiceTicketValidator(byte[] serviceTicket, String principal) {
    this.serviceTicket = serviceTicket;
    this.principal = principal;
  }

  public String run() throws Exception {
    try {
      GSSManager gssManager = GSSManager.getInstance();
      GSSName serviceName =
          gssManager.createName(principal, GSSName.NT_USER_NAME);

      GSSCredential serviceCredentials = gssManager
          .createCredential(serviceName, GSSCredential.INDEFINITE_LIFETIME,
              new Oid[]{KerberosUtil.getOidInstance("GSS_SPNEGO_MECH_OID"),
              KerberosUtil.getOidInstance("GSS_KRB5_MECH_OID")}, GSSCredential.ACCEPT_ONLY);

      GSSContext gssContext = gssManager.createContext(serviceCredentials);

      gssContext.acceptSecContext(this.serviceTicket, 0, this.serviceTicket.length);

      String clientName = gssContext.getSrcName().toString();

      gssContext.dispose();

      return clientName;
    } catch (Exception ex) {
      throw new PrivilegedActionException(ex);
    }
  }

}