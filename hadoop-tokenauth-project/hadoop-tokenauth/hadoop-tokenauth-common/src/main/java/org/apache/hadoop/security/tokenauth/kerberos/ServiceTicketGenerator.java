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

public class ServiceTicketGenerator implements PrivilegedExceptionAction<byte[]> {
  String principal;
  String servicePrincipal;

  public ServiceTicketGenerator(String principal, String servicePrincipal) {
    this.principal = principal;
    this.servicePrincipal = servicePrincipal;
  }

  public byte[] run() throws Exception {
    try {
      Oid kerberos5Oid = KerberosUtil.getOidInstance("GSS_KRB5_MECH_OID");
      Oid oid = KerberosUtil.getOidInstance("NT_GSS_KRB5_PRINCIPAL");
      GSSManager gssManager = GSSManager.getInstance();

      GSSName clientName = gssManager.createName(principal, GSSName.NT_USER_NAME);
      GSSName serviceName = gssManager.createName(servicePrincipal, oid);

      GSSCredential clientCredentials = gssManager
          .createCredential(clientName, GSSCredential.DEFAULT_LIFETIME, kerberos5Oid,
              GSSCredential.INITIATE_ONLY);

      GSSContext gssContext = gssManager
          .createContext(serviceName, kerberos5Oid, clientCredentials,
              GSSContext.DEFAULT_LIFETIME);

      byte[] serviceTicket = gssContext.initSecContext(new byte[0], 0, 0);
      gssContext.dispose();

      return serviceTicket;
    } catch (Exception ex) {
      throw new PrivilegedActionException(ex);
    }
  }

}
