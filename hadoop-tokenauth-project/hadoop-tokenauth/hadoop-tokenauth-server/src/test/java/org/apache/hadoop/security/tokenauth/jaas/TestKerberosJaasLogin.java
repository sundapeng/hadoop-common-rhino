package org.apache.hadoop.security.tokenauth.jaas;

import java.io.File;
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.util.HashSet;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.minikdc.KerberosSecurityTestcase;
import org.apache.hadoop.minikdc.MiniKdc;
import org.apache.hadoop.security.tokenauth.has.HASConfiguration;
import org.apache.hadoop.security.tokenauth.kerberos.KerberosCallback;
import org.apache.hadoop.security.tokenauth.kerberos.KerberosLoginConfiguration;
import org.apache.hadoop.security.tokenauth.kerberos.ServiceTicketGenerator;

import org.junit.Assert;
import org.junit.Test;
import static org.junit.Assert.assertEquals;

//-Djava.security.krb5.conf=/etc/krb5.conf
public class TestKerberosJaasLogin extends KerberosSecurityTestcase{
  
  @Test
  public void testMiniKdcStart() {
    MiniKdc kdc = getKdc();
    Assert.assertNotSame(0, kdc.getPort());
  }
  
  @Test
  public void testLogin() throws Exception {
    
    MiniKdc kdc = getKdc();
    File workDir = getWorkDir();
    
    String userPrincipal = "user";
    File userKeytab = new File(workDir, "user.keytab");
    kdc.createPrincipal(userKeytab, userPrincipal);
    
    String identityRpcPrincipal = "identityRpc";
    File identityRpcKeytab = new File(workDir, "identityRpc.keytab");
    kdc.createPrincipal(identityRpcKeytab, identityRpcPrincipal);
    
    String identityHttpPrincipal = "HTTP";
    File identityHttpKeytab = new File(workDir, "HTTP.keytab");
    kdc.createPrincipal(identityHttpKeytab, identityHttpPrincipal);

    Set<Principal> principals = new HashSet<Principal>();
    principals.add(new KerberosPrincipal(userPrincipal));

    Configuration conf = new HASConfiguration();
    conf.set(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_AUTHENTICATORS_KEY,
        "kerberos");
    conf.set(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_IDENTITY_SERVER_KEYTAB_KEY,
        identityRpcKeytab.getAbsolutePath());
    conf.set(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_IDENTITY_SERVER_PRINCIPAL_KEY,
        identityRpcPrincipal + "@" + kdc.getRealm());
    conf.set(HASConfiguration.
        HADOOP_SECURITY_TOKENAUTH_IDENTITY_SERVER_HTTP_KEYTAB_KEY,
        identityHttpKeytab.getAbsolutePath());
    conf.set(HASConfiguration.
        HADOOP_SECURITY_TOKENAUTH_IDENTITY_SERVER_HTTP_PRINCIPAL_KEY,
        identityHttpPrincipal + "@" + kdc.getRealm());
    byte[] serviceTicket = prepare(userKeytab.getAbsolutePath(), userPrincipal, conf);
    Login login = new LoginImpl(conf);
    int result = login.login();
    System.out.println(result);
    assertEquals(Login.NOTCOMPLETED, result);

    Callback[] callbacks = new Callback[2];
//    login.getRequiredCallbacks();
    callbacks[0] = new NameCallback("name");
    callbacks[1] = new KerberosCallback("service");

    for (Callback callback : callbacks) {
      if (callback instanceof KerberosCallback) {
        ((KerberosCallback) callback).setTicket(serviceTicket);
      }
    }

    result = login.login(callbacks);
    assertEquals(Login.SUCCEED, result);
  }

  private byte[] prepare(String keytab, String principal, Configuration conf) {
    // create a LoginContext based on the entry in the login.conf file

    Subject clientSubject = new Subject();
    LoginContext lc = null;
    byte[] serviceTicket = null;
    try {
      lc = new LoginContext("keytab-kerberos", clientSubject, null,
          new KerberosLoginConfiguration(keytab, principal));
      lc.login();
      serviceTicket = Subject
          .doAs(clientSubject, new ServiceTicketGenerator(principal, conf.get(
              HASConfiguration.HADOOP_SECURITY_TOKENAUTH_IDENTITY_SERVER_PRINCIPAL_KEY)));
    } catch (LoginException e) {
      e.printStackTrace();
    } catch (PrivilegedActionException e) {
      e.printStackTrace();
    }

    return serviceTicket;
  }
}
