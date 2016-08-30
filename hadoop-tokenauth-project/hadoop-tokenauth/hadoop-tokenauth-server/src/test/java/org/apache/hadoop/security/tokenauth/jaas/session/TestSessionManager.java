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

package org.apache.hadoop.security.tokenauth.jaas.session;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.tokenauth.has.HASConfiguration;
import org.apache.hadoop.security.tokenauth.jaas.Login;
import org.apache.hadoop.security.tokenauth.jaas.LoginImpl;
import org.apache.hadoop.security.tokenauth.jaas.session.LoginSession;
import org.apache.hadoop.security.tokenauth.jaas.session.SessionManager;
import org.junit.Test;

public class TestSessionManager {
  
  @Test
  public void testGetSession() throws Exception {
    Configuration conf = new HASConfiguration();
    conf.set(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_AUTHENTICATORS_KEY, "simple");
    LoginSession session;
    Login login;
    login = new LoginImpl(conf);
    
    session = SessionManager.get().newSession(login);
    long createTime = session.getCreationTime();
    String sessionID = session.getId();
    System.out.println("creationTime: " + createTime);
    System.out.println("sessionID: " + sessionID);
    
    session = SessionManager.get().getSession(sessionID);
    assertEquals(createTime, session.getCreationTime());
    assertEquals(sessionID, session.getId());
  }
  
  @Test
  public void testSetLogin() throws Exception {
    Configuration conf = new HASConfiguration();
    conf.set(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_AUTHENTICATORS_KEY, "simple");
    LoginSession session;
    Login login;
    login = new LoginImpl(conf);
    
    session = SessionManager.get().newSession(login);
    long createTime = session.getCreationTime();
    String sessionID = session.getId();
    System.out.println("creationTime: " + createTime);
    System.out.println("sessionID: " + sessionID);
    
    login = new LoginImpl(conf);
    session.setLogin(login);
    System.out.println(session.getLogin().getLoginStatus());
    login.login();
    System.out.println(session.getLogin().getLoginStatus());
    NameCallback nameCb = new NameCallback("username");
    nameCb.setName("root");
    login.login(new Callback[]{nameCb});
    System.out.println(session.getLogin().getLoginStatus());
  }
  
  @Test
  public void testExpire() throws Exception {
    Configuration conf = new HASConfiguration();
    conf.set(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_AUTHENTICATORS_KEY, "simple");
    LoginSession session;
    Login login;
    login = new LoginImpl(conf);
    
    session = SessionManager.get().newSession(login);
    System.out.println("creationTime: " + session.getCreationTime());
    System.out.println("sessionID: " + session.getId());
    assertFalse(session.expired());
    
    SessionManager sm = SessionManager.get();
    session = sm.newSession(login, 1000);
    Thread.sleep(1200);
    System.out.println("creationTime: " + session.getCreationTime());
    System.out.println("sessionID: " + session.getId());
    assertTrue(session.expired());
  }
}
