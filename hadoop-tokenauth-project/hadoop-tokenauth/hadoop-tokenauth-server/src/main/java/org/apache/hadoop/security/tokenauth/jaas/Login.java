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

import java.util.List;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;

import org.apache.hadoop.security.tokenauth.token.Attribute;

public interface Login {
  
  //login result
  public static final int SUCCEED = 0;
  public static final int FAILED = 1;
  public static final int NOTCOMPLETED = 2;
  public static final int RETRIED = 3;
  
  /**
   * return value can be one of 'SUCCEED', 'FAILED', 'NOTCOMPLETED' and 'RETRIED'
   * If 'FAILED', can use 'getFailure' to obtain failure cause
   * If 'NOTCOMPLETED', can use 'getRequiredCallbacks' to get required callbacks.
   * If 'RETRIED', means one of login module failed and allow retry, can use 'getFailure' 
   *   to obtain failure cause and use 'getRequiredCallbacks' to get required callbacks for retry.
   */
  int login();
  
  /**
   * login with callbacks. This method can be invoked multiple times, if there are 
   * multiple module in the authentication chain, and some of them require callbacks.
   */
  int login(Callback[] callbacks);
  
  /**
   * After login successfully or failed, can't call login again. Can use this 
   * method to get login status.
   */
  int getLoginStatus();
  
  /**
   * logout, return value can be one of 'SUCCEED', 'FAILED', 'NOTCOMPLETED' and 'RETRIED'
   */
  int logout();
  
  /**
   * After logout successfully or failed, can't call logout again. Can use this
   * method to get logout status.
   */
  int getLogoutStatus();
  
  /**
   * return the authenticated Subject.
   */
  Subject getSubject();
  
  /**
   * return the authenticated attributes
   */
  List<Attribute> getAttributes();
  
  /**
   * get the failure cause if login or logout failed.
   */
  String getFailure();
  
  /**
   * get the required callbacks if login not completed.
   */
  Callback[] getRequiredCallbacks();
}
