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

public abstract class SecretsManager {
  private static SecretsManager secretsManager;
  
  public static synchronized SecretsManager get() {
    if(secretsManager == null) {
      secretsManager = new DefaultSecretsManager();
    }
    return secretsManager;
  }
  
  /** If secrets for name don't exist, create one **/
  public abstract Secrets getSecrets(String name);
  
  public abstract void removeSecrets(String name);
}
