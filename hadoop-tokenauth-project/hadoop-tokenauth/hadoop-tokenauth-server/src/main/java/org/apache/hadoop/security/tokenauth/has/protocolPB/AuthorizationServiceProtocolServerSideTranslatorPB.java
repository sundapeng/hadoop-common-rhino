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

import java.io.IOException;

import org.apache.hadoop.ipc.ProtocolSignature;
import org.apache.hadoop.ipc.RPC;
import org.apache.hadoop.security.tokenauth.api.AuthorizationServiceProtocol;
import org.apache.hadoop.security.tokenauth.proto.AuthorizationServiceProtocolProtos;

import com.google.protobuf.RpcController;
import com.google.protobuf.ServiceException;

public class AuthorizationServiceProtocolServerSideTranslatorPB
    implements AuthorizationServiceProtocolPB {

  private final AuthorizationServiceProtocol server;

  public AuthorizationServiceProtocolServerSideTranslatorPB(
      AuthorizationServiceProtocol server) {
    this.server = server;
  }


  @Override
  public ProtocolSignature getProtocolSignature(String protocol,
      long clientVersion, int clientMethodsHash) throws IOException {
    if (!protocol.equals(RPC.getProtocolName(IdentityServiceProtocolPB.class))) {
      throw new IOException("Serverside implements " +
          RPC.getProtocolName(IdentityServiceProtocolPB.class) +
          ". The following requested protocol is unknown: " + protocol);
    }
    return ProtocolSignature.getProtocolSignature(clientMethodsHash,
        RPC.getProtocolVersion(IdentityServiceProtocolPB.class),
        IdentityServiceProtocolPB.class);
  }

  @Override
  public long getProtocolVersion(String protocol, long clientVersion) throws
      IOException {
    return RPC.getProtocolVersion(IdentityServiceProtocolPB.class);
  }

  @Override
  public AuthorizationServiceProtocolProtos.GetAccessTokenResponseProto getAccessToken(
      RpcController controller,
      AuthorizationServiceProtocolProtos.GetAccessTokenRequestProto proto) throws
      ServiceException {
    byte[] identityToken = PBHelper.convertAccessTokenRequest(proto);
    String protocol;
    if (proto.hasProtocol()) {
      protocol = proto.getProtocol();
    } else {
      throw new NullPointerException();
    }
    try {
      return PBHelper
          .convertAccessToken(server.getAccessToken(identityToken, protocol));
    } catch (IOException e) {
      throw new ServiceException(e);
    }
  }
}