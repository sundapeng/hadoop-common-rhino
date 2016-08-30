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

package org.apache.hadoop.security.tokenauth.secrets;

import java.util.Map;

abstract class SecretsSerializer {
  
  private static SecretsSerializer serializer;
  
  public static synchronized SecretsSerializer get() {
    if(serializer == null) {
      serializer = new KeyStoreSecretsSerializer();
    }
    return serializer;
  }
  
  /**
   * Load secrets map at initialize time
   */
  public abstract void loadSecretsMap(Map<String, Secrets> secretsMap);

  /**
   * Serialize the secrets.
   */
  public abstract void serializeSecrets(String name, Secrets secrets);
  
  /**
   * Delete secrets.
   */
  public abstract void deleteSecrets(String name);
}
