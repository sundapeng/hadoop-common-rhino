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

import org.apache.hadoop.security.tokenauth.jaas.Login;

public abstract class SessionManager {
  private static SessionManager sessionManager;
  
  public static synchronized SessionManager get() {
    if(sessionManager == null) {
      sessionManager = new HashSessionManager();
    }
    return sessionManager;
  }
  
  /**
   * Get session through session id.
   */
  public abstract LoginSession getSession(String id);
  
  /**
   * Create session with expires time measured
   * in milliseconds
   */
  public abstract LoginSession newSession(Login login, long expires);
  
  /**
   * 
   * Create session which never expires.
   */
  public abstract LoginSession newSession(Login login);
}
