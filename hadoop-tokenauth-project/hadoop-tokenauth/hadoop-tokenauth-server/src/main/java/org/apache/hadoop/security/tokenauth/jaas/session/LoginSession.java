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

import java.util.Enumeration;

import org.apache.hadoop.security.tokenauth.jaas.Login;

public interface LoginSession {
  
  /**
   * Returns the time when this session was created, measured
   * in milliseconds since midnight January 1, 1970 GMT.
   */
  long getCreationTime();
  
  /**
   * Returns a string containing the unique identifier assigned 
   * to this session.
   */
  String getId();
  
  /**
   * Returns the associated login.
   */
  Login getLogin();
  
  /**
   * Update associated login.
   */
  void setLogin(Login login);
  
  /**
   * Returns the object bound with the specified name in this session, or
   * <code>null</code> if no object is bound under the name.
   */
  Object getValue(String name);
  
  /**
   * Returns an <code>Enumeration</code> of <code>String</code> objects
   * containing the names of all the objects bound to this session. 
  */
  Enumeration<String> getNames();
  
  /**
   * Binds an object to this session, using the name specified.
   * If an object of the same name is already bound to the session,
   * the object is replaced.
   */
  void putValue(String name, Object value);
  
  /**
   * Removes the object bound with the specified name from
   * this session. If the session does not have an object
   * bound with the specified name, this method does nothing.
  */
  void removeValue(String name);
  
  /**
   * Invalidates this session then unbinds any objects bound
   * to it. 
   */
  void invalidate();
  
  /**
   * Is the session valid?
   */
  boolean isValid();
  
  /**
   * Is the session expired?
   */
  boolean expired();
}
