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

package org.apache.hadoop.security.tokenauth.web;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.hadoop.security.tokenauth.HASClientCallbackHandler;
import org.apache.hadoop.security.tokenauth.has.HASClient;

public class DefaultHASClientCallbackHandler implements HASClientCallbackHandler {
  private CallbackHandler callbackHandler;
  private HASClient hasClient;
  
  public DefaultHASClientCallbackHandler() {
  }
  
  public DefaultHASClientCallbackHandler(
      CallbackHandler callbackHandler, HASClient hasClient) {
    this.callbackHandler = callbackHandler;
    this.hasClient = hasClient;
  }
  
  public DefaultHASClientCallbackHandler(HASClient hasClient) {
    this.hasClient = hasClient;
  }

  @Override
  public void handle(Callback[] callbacks) throws IOException,
      UnsupportedCallbackException {
    if (callbackHandler != null) {
      callbackHandler.handle(callbacks);
    }
  }

  @Override
  public HASClient getHASClient() {
    return hasClient;
  }
}
