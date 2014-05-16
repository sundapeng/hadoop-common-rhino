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

package org.apache.hadoop.security.tokenauth.has.identity;

import java.io.IOException;
import java.util.Set;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.tokenauth.token.InvalidTokenException;
import org.apache.hadoop.security.tokenauth.token.impl.IdentityToken;

public abstract class IdentityTokenStorage {
  
  private static IdentityTokenStorage identityTokenStorage;
  
  public static IdentityTokenStorage get(Configuration conf) throws IllegalArgumentException{
    if(null == identityTokenStorage){
      try {
        // TODO: Initialize different identity token storage instance according to configuration after we implement them.
        identityTokenStorage= (IdentityTokenStorage) new DefaultIdentityTokenStorage(conf);
      } catch (ClassNotFoundException e) {
        throw new IllegalArgumentException(e);
      } catch (IOException e) {
        throw new IllegalArgumentException(e);
      }
    }
    return identityTokenStorage;
  }
  
  public abstract void put(IdentityTokenInfo tokenInfo);
  
  /**
   * Get a token's information.
   */
  public abstract IdentityTokenInfo get(long tokenId);
  
}
