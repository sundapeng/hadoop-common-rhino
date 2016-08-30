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

package org.apache.hadoop.security.tokenauth.token.impl;

import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;

import org.apache.hadoop.security.tokenauth.secrets.Secrets;
import org.apache.hadoop.security.tokenauth.util.WritableUtils;

public class AccessToken extends AbstractToken {
  public static final String NAME = "ACCESS-TOKEN";
  
  public AccessToken(Secrets secrets,
      String issuer, String user, long issueInstant, 
      long notBefore, long notOnOrAfter) {
    this(secrets, issuer, user, issueInstant, 
        notBefore, notOnOrAfter, false);
  }
  
  public AccessToken(Secrets secrets, String issuer, 
      String user, long issueInstant, long notBefore,
      long notOnOrAfter, boolean encrypted) {
    super(secrets, issuer, user, issueInstant, 
        notBefore, notOnOrAfter, encrypted);
  }
  
  public AccessToken(byte[] rawBytes) {
    super(rawBytes);
  }
  
  public AccessToken(byte[] rawBytes, Secrets secrets) {
    super(rawBytes, secrets);
  }
  
  public AccessToken(long id, Secrets secrets, String issuer, String user, long issueInstant,
      long notBefore, long notOnOrAfter, boolean encrypted) {
    super(id, secrets, issuer, user, issueInstant, notBefore, notOnOrAfter, encrypted);
  }

  @Override
  void writeHeaderFields(DataOutput out) throws IOException {
    WritableUtils.writeString(out, NAME);
    out.writeBoolean(isEncrypted());
  }

  @Override
  void readHeaderFields(DataInput in) throws IOException {
    String name = WritableUtils.readString(in);
    if(!NAME.equals(name)) {
      throw new InvalidToken("It's not a access token.");
    }
    setEncrypted(in.readBoolean());
  }
}
