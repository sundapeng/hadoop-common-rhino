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

package org.apache.hadoop.security.tokenauth.api;

import java.io.IOException;

import org.apache.hadoop.classification.InterfaceAudience.Public;

/**
 * This protocol is responsible for authentication 
 * and return identity token.
 */
public interface IdentityServiceProtocol {
  /**
   * Initial version of the protocol
   */
  public static final long versionID = 1L;
  
  @Public
  IdentityResponse authenticate(IdentityRequest request) throws IOException;
  
  /**
   * Admin or token owner can renew token if that token is renewable
   * @param identityToken the identitytoken of admin or token owner
   * @param tokenId id of token which will be cancelled.
   * @throws IOException
   */
  @Public
  byte[] renewToken(byte[] identityToken, long tokenId) throws IOException;
  
  /**
   * Admin or token owner can cancel token
   * @param identityToken the identitytoken of admin or token owner
   * @param tokenId id of token which will be cancelled.
   * @throws IOException
   */
  @Public
  void cancelToken(byte[] identityToken, long tokenId) throws IOException;
}
