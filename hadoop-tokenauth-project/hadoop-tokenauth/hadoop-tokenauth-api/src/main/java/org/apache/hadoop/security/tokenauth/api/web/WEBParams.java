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
package org.apache.hadoop.security.tokenauth.api.web;


import org.apache.hadoop.security.tokenauth.api.rest.RESTParams;

public class WEBParams {
  public static final String RELAYSTATE_PARAM = "relayState";
  public static final String PROTOCOL_PARAM = "protocol";
  public static final String IDENTITY_TOKEN_PARAM = "identityToken";
  public static final String ACCESS_TOKEN_PRARM = "accessToken";
  
  public static final String AUTHENTICATE_SERVLET_PATH_SPEC = 
      RESTParams.AUTHENTICATE_SERVLET_PATH_SPEC;
  public static final String AUTHORIZE_SERVLET_PATH_SPEC = 
      RESTParams.AUTHORIZE_SERVLET_PATH_SPEC;
}
