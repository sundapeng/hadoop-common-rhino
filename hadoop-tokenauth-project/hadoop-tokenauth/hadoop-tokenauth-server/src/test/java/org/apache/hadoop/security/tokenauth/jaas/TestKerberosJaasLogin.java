package org.apache.hadoop.security.tokenauth.jaas;

import java.security.PrivilegedActionException;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.tokenauth.has.HASConfiguration;
import org.apache.hadoop.security.tokenauth.kerberos.KerberosCallback;
import org.apache.hadoop.security.tokenauth.kerberos.KerberosLoginConfiguration;
import org.apache.hadoop.security.tokenauth.kerberos.ServiceTicketGenerator;

import org.junit.Test;
import static junit.framework.Assert.assertEquals;

//-Djava.security.krb5.conf=/etc/krb5.conf
public class TestKerberosJaasLogin {

  @Test
  public void testLogin() throws Exception {
/*
    String keytab = "/home/keytab/bdpe21.sh.intel.com/yarn.keytab";
    String principal = "yarn/bdpe21.sh.intel.com";


    Configuration conf = new HASConfiguration();
    conf.set(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_AUTHENTICATORS_KEY,
        "kerberos");

    conf.set(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_IDENTITY_SERVER_KEYTAB_KEY,
        "/home/keytab/bdpe21.sh.intel.com/HTTP.keytab");
    conf.set(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_IDENTITY_SERVER_PRINCIPAL_KEY,
        "HTTP/bdpe21.sh.intel.com@SH.INTEL.COM");
    byte[] serviceTicket = prepare(keytab, principal, conf);
    Login login = new LoginImpl(conf);


    int result = login.login();

    System.out.println(result);

    assertEquals(result, Login.NOTCOMPLETED);

    Callback[] callbacks = new Callback[2];
    //login.getRequiredCallbacks();
    callbacks[0] = new NameCallback("name");
    callbacks[1] = new KerberosCallback("service");

    for (Callback callback : callbacks) {
      if (callback instanceof NameCallback) {
        ((NameCallback) callback).setName(principal);
      } else if (callback instanceof KerberosCallback) {
        ((KerberosCallback) callback).setTicket(serviceTicket);
      }
    }


    result = login.login(callbacks);
    //System.out.println(result);
    assertEquals(result, Login.SUCCEED);
*/
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
