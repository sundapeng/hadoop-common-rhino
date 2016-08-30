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

import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.hadoop.ipc.ProtocolSignature;
import org.apache.hadoop.ipc.RPC;
import org.apache.hadoop.security.tokenauth.api.IdentityRequest;
import org.apache.hadoop.security.tokenauth.api.IdentityResponse;
import org.apache.hadoop.security.tokenauth.has.protocol.IdentityServiceProtocals;
import org.apache.hadoop.security.tokenauth.proto.IdentityServiceProtocolProtos.ValidateTokenRequestProto;
import org.apache.hadoop.security.tokenauth.proto.IdentityServiceProtocolProtos.ValidateTokenResponseProto;
import org.apache.hadoop.security.tokenauth.proto.SecretsProtocolProtos;
import org.apache.hadoop.security.tokenauth.proto.IdentityServiceProtocolProtos;
import org.apache.hadoop.security.tokenauth.proto.IdentityServiceProtocolProtos.CancelTokenRequestProto;
import org.apache.hadoop.security.tokenauth.proto.IdentityServiceProtocolProtos.RenewTokenRequestProto;
import org.apache.hadoop.security.tokenauth.proto.IdentityServiceProtocolProtos.RenewTokenResponseProto;
import org.apache.hadoop.security.tokenauth.proto.IdentityServiceProtocolProtos.VoidResponseProto;

import com.google.protobuf.RpcController;
import com.google.protobuf.ServiceException;

public class IdentityServiceProtocolServerSideTranslatorPB
    implements IdentityServiceProtocolPB, SecretsProtocolPB {

  private final IdentityServiceProtocals server;

  public IdentityServiceProtocolServerSideTranslatorPB(
      IdentityServiceProtocals server) {
    this.server = server;
  }

  @Override
  public IdentityServiceProtocolProtos.ResponseProto authenticate(
      RpcController controller,
      IdentityServiceProtocolProtos.RequestProto proto) throws ServiceException {
    IdentityRequest request = PBHelper.convert(proto);
    IdentityResponse response;
    try {
      response = server.authenticate(request);
      return PBHelper.convert(response);
    } catch (IOException e) {
      throw new ServiceException(e);
    } catch (UnsupportedCallbackException e) {
      throw new ServiceException(e);
    }
  }
  
  @Override
  public RenewTokenResponseProto renewToken(RpcController controller,
      RenewTokenRequestProto request) throws ServiceException {
    try {
      byte[] identityToken = server.renewToken(
          request.getIdentityToken().toByteArray(), request.getTokenId());
      return PBHelper.convert(identityToken);
    } catch (IOException e) {
      throw new ServiceException(e);
    }
  }

  @Override
  public VoidResponseProto cancelToken(RpcController controller,
      CancelTokenRequestProto request) throws ServiceException {
    try {
      server.cancelToken(request.getIdentityToken().toByteArray(), request.getTokenId());
      return VoidResponseProto.getDefaultInstance();
    } catch (IOException e) {
      throw new ServiceException(e);
    }
  }
  
  @Override
  public ValidateTokenResponseProto validateToken(RpcController controller,
      ValidateTokenRequestProto request) throws ServiceException {
    try{
      boolean result = server.validateToken(request.getIdentityToken().toByteArray());
      return PBHelper.convert(result);
    } catch (IOException e){
      throw new ServiceException(e);
    }
  }

  @Override
  public SecretsProtocolProtos.GetSecretsResponseProto getSecrets(
      RpcController controller,
      SecretsProtocolProtos.GetSecretsRequestProto proto) throws
      ServiceException {
    byte[] identityToken = PBHelper.convert(proto);
    String protocol = proto.getProtocol();
    try {
      return PBHelper.convert(server.getSecrets(identityToken, protocol));
    } catch (IOException e) {
      throw new ServiceException(e);
    }
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
}