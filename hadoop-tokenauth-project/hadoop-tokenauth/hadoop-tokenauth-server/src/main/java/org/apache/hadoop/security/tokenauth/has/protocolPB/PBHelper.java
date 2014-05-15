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
package org.apache.hadoop.security.tokenauth.has.protocolPB;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.SecretKey;

import org.apache.hadoop.security.tokenauth.proto.SecretsProtocolProtos;
import org.apache.hadoop.security.tokenauth.secrets.Secrets;

import com.google.protobuf.ByteString;

public class PBHelper extends org.apache.hadoop.security.tokenauth.api.pb.PBHelper {
  
  public static byte[] convert(SecretsProtocolProtos.GetSecretsRequestProto proto) {
    if (proto.hasIdentityToken()) {
      return proto.getIdentityToken().toByteArray();
    }
    return new byte[0];
  }

  public static SecretsProtocolProtos.GetSecretsRequestProto convert(
      byte[] identityToken, String protocol) {
    SecretsProtocolProtos.GetSecretsRequestProto.Builder builder =
        SecretsProtocolProtos.GetSecretsRequestProto.newBuilder();
    if (identityToken != null) {
      builder.setIdentityToken(ByteString.copyFrom(identityToken));
    }
    builder.setProtocol(protocol);
    return builder.build();
  }

  public static Secrets convert(
      SecretsProtocolProtos.GetSecretsResponseProto proto) throws
      InvalidKeyException {
    final SecretKey secretKey;
    final PrivateKey privKey;
    if (proto.hasSecretKey()) {
      secretKey = convert2SecretKey(proto.getSecretKey());
    } else {
      throw new NullPointerException();
    }
    if (proto.hasPrivateKey()) {
      privKey = convert2PrivateKey((proto.getPrivateKey()));
    } else {
      throw new NullPointerException();
    }
    
    return new Secrets() {
      @Override
      public SecretKey getSecretKey() {
        return secretKey;
      }

      @Override
      public PublicKey getPublicKey() {
        return null;
      }

      @Override
      public PrivateKey getPrivateKey() {
        return privKey;
      }
    };
  }

  public static SecretsProtocolProtos.GetSecretsResponseProto convert(
      Secrets response) {
    SecretsProtocolProtos.GetSecretsResponseProto.Builder builder =
        SecretsProtocolProtos.GetSecretsResponseProto.newBuilder();
    if (response.getPrivateKey() != null) {
      builder.setPrivateKey(convert(response.getPrivateKey()));
    }
    if (response.getSecretKey() != null) {
      builder.setSecretKey(convert(response.getSecretKey()));
    }
    return builder.build();
  }
}
