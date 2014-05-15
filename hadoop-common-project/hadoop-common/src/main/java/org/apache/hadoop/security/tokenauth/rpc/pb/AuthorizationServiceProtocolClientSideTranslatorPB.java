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
import javax.net.SocketFactory;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.ipc.ProtobufHelper;
import org.apache.hadoop.ipc.ProtobufRpcEngine;
import org.apache.hadoop.ipc.ProtocolTranslator;
import org.apache.hadoop.ipc.RPC;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.tokenauth.api.AuthorizationServiceProtocol;
import org.apache.hadoop.security.tokenauth.api.pb.PBHelper;
import org.apache.hadoop.security.tokenauth.proto.AuthorizationServiceProtocolProtos;

import com.google.protobuf.RpcController;
import com.google.protobuf.ServiceException;

public class AuthorizationServiceProtocolClientSideTranslatorPB
    implements Closeable, ProtocolTranslator, AuthorizationServiceProtocol {

  private final AuthorizationServiceProtocolPB rpcProxy;

  private final static RpcController NULL_CONTROLLER = null;

  public AuthorizationServiceProtocolClientSideTranslatorPB(Configuration conf,
      InetSocketAddress address, SocketFactory socketFactory, int timeout) 
      throws IOException {
    RPC.setProtocolEngine(conf, AuthorizationServiceProtocolPB.class,
        ProtobufRpcEngine.class);
    rpcProxy = RPC.getProxy(AuthorizationServiceProtocolPB.class,
        RPC.getProtocolVersion(AuthorizationServiceProtocolPB.class), address,
        UserGroupInformation.createRemoteUser("HASClient"), conf, socketFactory, timeout);
  }

  @Override
  public void close() throws IOException {
    RPC.stopProxy(rpcProxy);
  }

  @Override
  public Object getUnderlyingProxyObject() {
    return rpcProxy;
  }

  @Override
  public byte[] getAccessToken(byte[] identityToken, String protocol) throws
      IOException {
    try {
      AuthorizationServiceProtocolProtos.GetAccessTokenRequestProto proto =
          PBHelper.convertAccessTokenRequest(identityToken, protocol);
      AuthorizationServiceProtocolProtos.GetAccessTokenResponseProto response = rpcProxy.getAccessToken(
          NULL_CONTROLLER, proto);
      return PBHelper.convertAccessToken(response);
    } catch (ServiceException e) {
      throw ProtobufHelper.getRemoteException(e);
    }
  }
}
