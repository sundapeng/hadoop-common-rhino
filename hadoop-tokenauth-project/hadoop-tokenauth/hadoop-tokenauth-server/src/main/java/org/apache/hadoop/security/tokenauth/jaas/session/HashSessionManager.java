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

import java.security.SecureRandom;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.security.tokenauth.jaas.Login;
import org.apache.hadoop.util.Time;

public class HashSessionManager extends SessionManager {
  private static final Log LOG =  LogFactory.getLog(HashSessionManager.class);
  private Map<String, LoginSession> sessions;
  private static final long SCAN_INTERVAL = 15 * 60 * 1000; 
  private static final long DAY = 24 * 60 * 60 * 1000;
  
  HashSessionManager() {
    sessions = new HashMap<String, LoginSession>();
    
    Thread monitor = new Thread(new Runnable() {

      @Override
      public void run() {
        while (true) {
          try {
            Thread.sleep(SCAN_INTERVAL);
            
            Set<LoginSession> expiredSessions = new HashSet<LoginSession>();
            synchronized(HashSessionManager.this) {
              Iterator<LoginSession> iter = sessions.values().iterator();
              while(iter.hasNext()) {
                LoginSession session = iter.next();
                if (session.expired() || !session.isValid()) {
                  expiredSessions.add(session);
                }
              }
              
              for (LoginSession session : expiredSessions) {
                sessions.remove(session.getId());
              }
            }
          } catch (InterruptedException e) {
            LOG.warn("Terminating monitor thread");
            return;
          }
        }
      }
      
    });
    monitor.setDaemon(true);
    monitor.setName("Session monitor");
    monitor.start();
  }

  @Override
  public LoginSession getSession(String id) {
    synchronized(HashSessionManager.this) {
      return sessions.get(id);
    }
  }
  
  @Override
  public LoginSession newSession(Login login) {
    return newSession(login, DAY); //default expires is one day
  }

  @Override
  public LoginSession newSession(Login login, long expires) {    
    LoginSession session = new LoginSession() {
      private Login login;
      private long expires;
      private long creationTime;
      private String sessionId;
      private boolean valid = true;
      private ConcurrentHashMap<String,Object> attributes;
      
      private LoginSession init(Login login, long expires) {
        attributes = new ConcurrentHashMap<String,Object>();
        creationTime = Time.now();
        sessionId = String.valueOf((new SecureRandom()).nextLong());
        this.login = login;
        this.expires = expires;
        
        return this;
      }

      @Override
      public long getCreationTime() {
        return creationTime;
      }

      @Override
      public String getId() {
        return sessionId;
      }

      @Override
      public synchronized Login getLogin() {
        return login;
      }
      
      @Override
      public synchronized void setLogin(Login login) {
        this.login = login;
      }
      
      @Override
      public Object getValue(String name) {
        return attributes.get(name);
      }

      @Override
      public Enumeration<String> getNames() {
        return attributes.keys();
      }

      @Override
      public void putValue(String name, Object value) {
        attributes.put(name, value);
      }

      @Override
      public void removeValue(String name) {
        attributes.remove(name);
      }

      @Override
      public synchronized void invalidate() {
        valid = false;
      }
      
      @Override
      public synchronized boolean isValid() {
        return valid;
      }

      @Override
      public boolean expired() {
        if(expires < 0) {
          return false;
        }
        return Time.now() - creationTime >= expires ? true : false;  
      }

    }.init(login, expires);
    
    synchronized(HashSessionManager.this) {
      sessions.put(session.getId(), session);
    }
    return session;
  }
}
