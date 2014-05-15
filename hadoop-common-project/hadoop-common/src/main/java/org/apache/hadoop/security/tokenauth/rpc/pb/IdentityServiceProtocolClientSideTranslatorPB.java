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

package org.apache.hadoop.security.tokenauth.rpc.pb;

import java.io.Closeable;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.InvalidKeyException;
import javax.net.SocketFactory;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.ipc.ProtobufHelper;
import org.apache.hadoop.ipc.ProtobufRpcEngine;
import org.apache.hadoop.ipc.ProtocolTranslator;
import org.apache.hadoop.ipc.RPC;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.tokenauth.api.IdentityRequest;
import org.apache.hadoop.security.tokenauth.api.IdentityResponse;
import org.apache.hadoop.security.tokenauth.api.IdentityServiceProtocol;
import org.apache.hadoop.security.tokenauth.api.pb.PBHelper;
import org.apache.hadoop.security.tokenauth.proto.IdentityServiceProtocolProtos;
import org.apache.hadoop.security.tokenauth.proto.IdentityServiceProtocolProtos.CancelTokenRequestProto;
import org.apache.hadoop.security.tokenauth.proto.IdentityServiceProtocolProtos.RenewTokenRequestProto;

import com.google.protobuf.ByteString;
import com.google.protobuf.RpcController;
import com.google.protobuf.ServiceException;

public class IdentityServiceProtocolClientSideTranslatorPB
    implements Closeable, ProtocolTranslator, IdentityServiceProtocol {

  private final IdentityServiceProtocolPB rpcProxy;

  private final static RpcController NULL_CONTROLLER = null;

  public IdentityServiceProtocolClientSideTranslatorPB(Configuration conf,
      InetSocketAddress address, SocketFactory socketFactory, int timeout) 
      throws IOException {
    RPC.setProtocolEngine(conf, IdentityServiceProtocolPB.class,
        ProtobufRpcEngine.class);
    rpcProxy = RPC.getProxy(IdentityServiceProtocolPB.class,
        RPC.getProtocolVersion(IdentityServiceProtocolPB.class), address,
        UserGroupInformation.createRemoteUser("HASClient"), conf, socketFactory, timeout);
  }

  @Override
  public void close() throws IOException {
    RPC.stopProxy(rpcProxy);
  }

  @Override
  public IdentityResponse authenticate(IdentityRequest request) throws IOException {
    IdentityResponse response;
    try {
      IdentityServiceProtocolProtos.RequestProto proto =
          PBHelper.convert(request);
      response = PBHelper.convert(rpcProxy.authenticate(NULL_CONTROLLER, proto));
      return response;
    } catch (ServiceException e) {
      throw ProtobufHelper.getRemoteException(e);
    } catch (UnsupportedCallbackException e) {
      throw ProtobufHelper.getRemoteException(new ServiceException(e));
    } catch (InvalidKeyException e) {
      throw ProtobufHelper.getRemoteException(new ServiceException(e));
    }
  }

  @Override
  public byte[] renewToken(byte[] identityToken, long tokenId) throws IOException {
    try {
      RenewTokenRequestProto proto =
          RenewTokenRequestProto.newBuilder().
          setIdentityToken(ByteString.copyFrom(identityToken))
          .setTokenId(tokenId).build();
      return PBHelper.convert(rpcProxy.renewToken(NULL_CONTROLLER, proto));
    } catch (ServiceException e) {
      throw ProtobufHelper.getRemoteException(e);
    }
  }

  @Override
  public void cancelToken(byte[] identityToken, long tokenId)
      throws IOException {
    try {
      CancelTokenRequestProto proto = 
          CancelTokenRequestProto.newBuilder().
          setIdentityToken(ByteString.copyFrom(identityToken))
          .setTokenId(tokenId).build();
      rpcProxy.cancelToken(NULL_CONTROLLER, proto);
    } catch (ServiceException e) {
      throw ProtobufHelper.getRemoteException(e);
    }
  }

  @Override
  public Object getUnderlyingProxyObject() {
    return rpcProxy;
  }
}
