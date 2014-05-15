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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.tokenauth.token.Attribute;

public interface AuthenticationContext {
  /**
   * Returns Hadoop configuration
   */
  Configuration getConf();
  
  /**
   * Set the handling module
   */
  void setHandlingModule(LoginModule module);
  
  /**
   * Return the login attributes
   */
  List<Attribute> getAttributes();
  
  /**
   * Return HttpServletRequest instance if login using http.
   */
  HttpServletRequest getHttpRequest();
  
  /**
   * Return HttpServletResponse instance if login using http.
   */
  HttpServletResponse getHttpResponse();
}
