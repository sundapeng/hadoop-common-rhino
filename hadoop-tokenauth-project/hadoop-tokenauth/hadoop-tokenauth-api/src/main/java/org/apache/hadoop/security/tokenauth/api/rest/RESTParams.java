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
package org.apache.hadoop.security.tokenauth.api.rest;

public class RESTParams {
  public static final String IDENTITY_TOKEN = "identityToken";
  public static final String ACCESS_TOKEN = "accessToken";
  public static final String TOKEN_ID = "tokenId";
  public static final String PROTOCOL = "protocol";
  
  public static final String PATH_V1 = "/ws/v1";
  public static final String AUTHENTICATE_SERVLET_PATH_SPEC = "/authenticate";
  public static final String AUTHORIZE_SERVLET_PATH_SPEC = "/authorize";
  public static final String RENEW_TOKEN_PATH_SPEC = "/renewToken";
  public static final String CANCEL_TOKEN_PATH_SPEC = "/cancelToken";
}
