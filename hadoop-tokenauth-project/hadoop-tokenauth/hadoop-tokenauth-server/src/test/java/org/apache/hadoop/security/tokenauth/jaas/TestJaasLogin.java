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

import static org.junit.Assert.assertEquals;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.tokenauth.has.HASConfiguration;
import org.junit.Test;

public class TestJaasLogin {
  
  @Test
  public void testLogin() throws Exception {
    Configuration conf = new HASConfiguration();
    conf.set(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_AUTHENTICATORS_KEY, "ldap");
    conf.set(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_LDAP_URL_KEY, "ldap://10.239.47.131");
    conf.set(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_LDAP_BIND_USER_KEY, "CN=HadoopAdmin,CN=Users,DC=ta,DC=sh,DC=intel,DC=com");
    conf.set(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_LDAP_BIND_PASSWORD_KEY, "Front123");
    conf.set(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_LDAP_BASE_DN_KEY, "CN=Users,DC=ta,DC=sh,DC=intel,DC=com");
    conf.set(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_LDAP_QUERY_ATTRIBUTES_KEY, "displayName,userPrincipalName");
    Login login = new LoginImpl(conf);
    
    
    int result = login.login();
    
    assertEquals(result, Login.NOTCOMPLETED);
    
    NameCallback nameCb = new NameCallback("username");
    nameCb.setName("hdfs");
    PasswordCallback pwdCb = new PasswordCallback("password", false);
    pwdCb.setPassword("Front123".toCharArray());
    
    result = login.login(new Callback[]{nameCb, pwdCb});
    
    assertEquals(result, Login.SUCCEED);
    
    System.out.println(login.getAttributes());
  }
  
  @Test
  public void testSimpleLogin() throws Exception {
    Configuration conf = new HASConfiguration();
    conf.set(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_AUTHENTICATORS_KEY, "simple");
    
    Login login = new LoginImpl(conf);
   
    int result = login.login();
    
    assertEquals(result, Login.NOTCOMPLETED);
    
    NameCallback nameCb = new NameCallback("username");
    nameCb.setName("test");
    
    result = login.login(new Callback[]{nameCb});
    
    assertEquals(result, Login.FAILED);
    
    nameCb.setName("root");
    
    login = new LoginImpl(conf);
    result = login.login(new Callback[]{nameCb});
    
    assertEquals(result, Login.SUCCEED);
    assertEquals(login.getLoginStatus(), Login.SUCCEED);
    
    System.out.println(login.getAttributes());
    
    result = login.logout();
    assertEquals(result, Login.SUCCEED);
    assertEquals(login.getLogoutStatus(), Login.SUCCEED);
  }
}
