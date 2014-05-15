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

package org.apache.hadoop.security.tokenauth.token;

import java.security.Principal;
import java.util.List;

import org.apache.hadoop.security.tokenauth.Writable;

/**
 * Token represents login result, or ticket to 
 * access resources. Token many includes many attributes.
 * Token should be signed and can be encrypted. 
 * Token is valid in its lifetime.
 */
public interface Token extends Writable {
  /**
   * Return token id
   */
  long getId();
  
  /**
   * Return token principal, a token can only have 
   * one principal
   */
  Principal getPrincipal();
  
  /**
   * Return attributes of the token, some important 
   * information may be include in token, such as groups.
   */
  List<Attribute> getAttributes();
  
  /**
   * The time when a token is created.
   */
  long getCreationTime();
  
  /**
   * When will a token expire.
   */
  long getExpiryTime();
}
