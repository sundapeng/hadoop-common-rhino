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

package org.apache.hadoop.security.tokenauth.authorize.policy;

import java.util.Set;

import org.apache.hadoop.security.tokenauth.token.Attribute;
import org.apache.hadoop.security.tokenauth.token.Token;
import org.apache.hadoop.security.tokenauth.token.TokenUtils;

public class EvaluationContext {
  private Token token;
  private String protocol;
  private String ip;
  
  public EvaluationContext(Token token) {
    this.token = token;
  }
  
  public EvaluationContext(Token token, String protocol) {
    this.token = token;
    this.protocol = protocol;
  }
  
  public EvaluationContext(Token token, String protocol, String ip) {
    this.token = token;
    this.protocol = protocol;
    this.ip = ip;
  }
  
  public String getProtocol() {
    return protocol;
  }
  
  public String getIP() {
    return ip;
  }
  
  public String getUser() {
    return token.getPrincipal().getName();
  }
  
  public String[] getGroups() {
    return TokenUtils.getGroups(token);
  }
  
  public Set<Object> getVariableValues(String name) {
    Attribute attribute = TokenUtils.getAttribute(token, name);
    Set<Object> values = attribute.getValues();
    
    return values;
  }
}
