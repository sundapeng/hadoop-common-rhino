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

package org.apache.hadoop.security.tokenauth.cache;

import java.io.IOException;
import java.util.List;

import javax.security.auth.callback.Callback;

import org.apache.hadoop.security.tokenauth.has.HASClient;

public abstract class TokenSerializer {
  
  private static TokenSerializer serializer;
  
  public static synchronized TokenSerializer get() {
    if(serializer == null) {
      serializer = new DefaultTokenSerializer();
    }
    return serializer;
  }
  
  public abstract void saveToken(byte[] token) throws IOException;
  
  public abstract byte[] readToken() throws IOException;
  
  public abstract void saveAuthnFile(List<Callback> callbacks, String username,
      String authnPath, List<Callback> savedOnlyCallback,
      List<Class<? extends Callback>> readOnlyCallback) throws IOException;
  
  public abstract List<Callback> getCallbacks(HASClient 
      hasClient, String principal, String authnFilePath) throws IOException;

}
