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
package org.apache.hadoop.security.tokenauth.shell;

import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.classification.InterfaceStability;
import org.apache.hadoop.security.tokenauth.has.HASClient;
import org.apache.hadoop.security.tokenauth.rpc.HASRpcClient;

/**
 * An abstract class for the execution of a tokenAuth command
 */
@InterfaceAudience.Private
@InterfaceStability.Evolving
abstract public class TokenCommand extends Command {

  protected HASClient hasClient;

  public static void registerCommands(CommandFactory factory) {
    factory.registerCommands(TokenInit.class);
    factory.registerCommands(GenAuthnFile.class);
  }

  protected void ensureHASClientInit() {
    if (hasClient == null ){
      synchronized(TokenCommand.class) {
        if (hasClient == null) {
          hasClient = new HASRpcClient(getConf());
        }
      }
    }
  }

}
