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
package org.apache.hadoop.security.tokenauth.api.pb;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.TextInputCallback;
import javax.security.auth.callback.TextOutputCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.RealmCallback;

import org.apache.hadoop.security.tokenauth.api.IdentityRequest;
import org.apache.hadoop.security.tokenauth.api.IdentityResponse;
import org.apache.hadoop.security.tokenauth.kerberos.KerberosCallback;
import org.apache.hadoop.security.tokenauth.proto.AuthorizationServiceProtocolProtos;
import org.apache.hadoop.security.tokenauth.proto.IdentityServiceProtocolProtos;
import org.apache.hadoop.security.tokenauth.proto.TokenAuthProtos;

import com.google.protobuf.ByteString;
import sun.security.provider.DSAPrivateKey;
import sun.security.provider.DSAPublicKeyImpl;

public class PBHelper {
  
  public static IdentityServiceProtocolProtos.CallbackProto convert(
      Callback cb) throws UnsupportedCallbackException {
    IdentityServiceProtocolProtos.CallbackProto.Builder builder =
        IdentityServiceProtocolProtos.CallbackProto.newBuilder();
    if (cb != null) {
      if (cb instanceof NameCallback) {
        NameCallback nameCb = (NameCallback) cb;
        builder.setNameCb(convert(nameCb));
      } else if (cb instanceof PasswordCallback) {
        PasswordCallback pwdCb = (PasswordCallback) cb;
        builder.setPwCb(convert(pwdCb));
      } else if (cb instanceof RealmCallback) {
        RealmCallback realmCallback = (RealmCallback) cb;
        builder.setRealmCb(convert(realmCallback));
      } else if (cb instanceof TextInputCallback) {
        TextInputCallback txtInCb = (TextInputCallback) cb;
        builder.setTxtInCb(convert(txtInCb));
      } else if (cb instanceof TextOutputCallback) {
        TextOutputCallback txtOutCb = (TextOutputCallback) cb;
        builder.setTxtOutCb(convert(txtOutCb));
      } else if (cb instanceof KerberosCallback) {
        KerberosCallback kbCallBack = (KerberosCallback) cb;
        builder.setKerberosCb(convert(kbCallBack));
      } else {
        throw new UnsupportedCallbackException(cb);
      }
    }
    
    return builder.build();
  }
  
  public static Callback convert(
      IdentityServiceProtocolProtos.CallbackProto callbackProto) {
    Callback callback = null;
    if (callbackProto.hasNameCb()) {
      NameCallback ncb = convert(callbackProto.getNameCb());
      callback = ncb;
    }
    if (callbackProto.hasRealmCb()) {
      RealmCallback rcb = convert(callbackProto.getRealmCb());
      callback = rcb;
    }
    if (callbackProto.hasPwCb()) {
      PasswordCallback pcb = convert(callbackProto.getPwCb());
      callback = pcb;
    }
    if (callbackProto.hasTxtInCb()) {
      TextInputCallback tcb = convert(callbackProto.getTxtInCb());
      callback = tcb;
    }
    if (callbackProto.hasTxtOutCb()) {
      TextOutputCallback tcb = convert(callbackProto.getTxtOutCb());
      callback = tcb;
    }
    if (callbackProto.hasKerberosCb()) {
      KerberosCallback kbcb = convert(callbackProto.getKerberosCb());
      callback = kbcb;
    }
    return callback;
  }

  public static IdentityServiceProtocolProtos.CallbacksProto convert(
      Callback[] cbs) throws UnsupportedCallbackException {
    IdentityServiceProtocolProtos.CallbacksProto.Builder builder =
        IdentityServiceProtocolProtos.CallbacksProto.newBuilder();
    if (cbs != null) {
      for (Callback cb : cbs) {
        builder.addCb(convert(cb));
      }
    }
    return builder.build();
  }

  public static Callback[] convert(
      IdentityServiceProtocolProtos.CallbacksProto callbacksProto) {
    List<Callback> callbacks = new ArrayList<Callback>();
    if (callbacksProto.getCbCount() > 0) {
      for (int i=0; i < callbacksProto.getCbCount(); i++) {
        Callback cb = convert(callbacksProto.getCb(i));
        callbacks.add(cb);
      }
    }
    Callback[] callbackArray = new Callback[callbacks.size()];
    callbackArray = callbacks.toArray(callbackArray);
    return callbackArray;
  }

  public static RealmCallback convert(
      IdentityServiceProtocolProtos.RealmCallbackProto proto) {
    RealmCallback rcb;
    if (!proto.hasPrompt()) throw new NullPointerException();
    if (proto.hasDefaultRealm()) {
      rcb = new RealmCallback(proto.getPrompt(), proto.getDefaultRealm());
    } else {
      rcb = new RealmCallback(proto.getPrompt());
    }
    if (proto.hasInputRealm()) {
      rcb.setText(proto.getInputRealm());
    }
    return rcb;
  }

  public static IdentityServiceProtocolProtos.RealmCallbackProto convert(
      RealmCallback realm) {
    IdentityServiceProtocolProtos.RealmCallbackProto.Builder builder =
        IdentityServiceProtocolProtos.RealmCallbackProto.newBuilder();
    builder.setPrompt(realm.getPrompt());
    if (realm.getDefaultText() != null) {
      builder.setDefaultRealm(realm.getDefaultText());
    }
    if (realm.getText() != null) {
      builder.setInputRealm(realm.getText());
    }
    return builder.build();
  }

  public static NameCallback convert(
      IdentityServiceProtocolProtos.NameCallbackProto proto) {
    NameCallback ncb;
    if (!proto.hasPrompt()) throw new NullPointerException();
    if (proto.hasDefaultName()) {
      ncb = new NameCallback(proto.getPrompt(), proto.getDefaultName());
    } else {
      ncb = new NameCallback(proto.getPrompt());
    }
    if (proto.hasInputName()) {
      ncb.setName(proto.getInputName());
    }
    return ncb;
  }

  public static IdentityServiceProtocolProtos.NameCallbackProto convert(
      NameCallback nameCallback) {
    IdentityServiceProtocolProtos.NameCallbackProto.Builder builder =
        IdentityServiceProtocolProtos.NameCallbackProto.newBuilder();
    builder.setPrompt(nameCallback.getPrompt());
    if (nameCallback.getName() != null) {
      builder.setInputName(nameCallback.getName());
    }
    if (nameCallback.getDefaultName() != null) {
      builder.setDefaultName(nameCallback.getDefaultName());
    }
    return builder.build();
  }

  public static PasswordCallback convert(
      IdentityServiceProtocolProtos.PasswordCallbackProto proto) {
    PasswordCallback pwCallBack;
    if (!proto.hasPrompt()) throw new NullPointerException();
    pwCallBack = new PasswordCallback(proto.getPrompt(), proto.getEchoOn());
    if (proto.hasInputPassword()) {
      pwCallBack.setPassword(proto.getInputPassword().toCharArray());
    }
    return pwCallBack;
  }

  public static IdentityServiceProtocolProtos.PasswordCallbackProto convert(
      PasswordCallback pwCallback) {
    IdentityServiceProtocolProtos.PasswordCallbackProto.Builder builder =
        IdentityServiceProtocolProtos.PasswordCallbackProto.newBuilder();
    builder.setPrompt(pwCallback.getPrompt());
    builder.setEchoOn(pwCallback.isEchoOn());
    if (pwCallback.getPassword() != null) {
      builder.setInputPassword(new String(pwCallback.getPassword()));
    }
    return builder.build();
  }

  public static TextInputCallback convert(
      IdentityServiceProtocolProtos.TextInputCallbackProto proto) {
    TextInputCallback textInCallback;
    if (!proto.hasPrompt()) throw new NullPointerException();
    if (proto.hasDefaultText()) {
      textInCallback =
          new TextInputCallback(proto.getPrompt(), proto.getDefaultText());
    } else {
      textInCallback = new TextInputCallback(proto.getPrompt());
    }
    if (proto.hasInputText()) {
      textInCallback.setText(proto.getInputText());
    }
    return textInCallback;
  }

  public static IdentityServiceProtocolProtos.TextInputCallbackProto convert(
      TextInputCallback ticb) {
    IdentityServiceProtocolProtos.TextInputCallbackProto.Builder builder =
        IdentityServiceProtocolProtos.TextInputCallbackProto.newBuilder();
    builder.setPrompt(ticb.getPrompt());
    if (ticb.getDefaultText() != null) {
      builder.setDefaultText(ticb.getDefaultText());
    }
    if (ticb.getText() != null) {
      builder.setInputText(ticb.getText());
    }
    return builder.build();
  }
  
  public static TextOutputCallback convert(
      IdentityServiceProtocolProtos.TextOutputCallbackProto proto) {
    TextOutputCallback textOutCallback = null;
    if (!proto.hasMessageType() || !proto.hasMessage()) 
      throw new NullPointerException();
    if (proto.hasMessage()) {
      textOutCallback = 
          new TextOutputCallback(proto.getMessageType(), proto.getMessage());
    }
    
    return textOutCallback;
  }
  
  public static IdentityServiceProtocolProtos.TextOutputCallbackProto convert(
      TextOutputCallback tocb) {
    IdentityServiceProtocolProtos.TextOutputCallbackProto.Builder builder = 
        IdentityServiceProtocolProtos.TextOutputCallbackProto.newBuilder();
    builder.setMessageType(tocb.getMessageType());
    if (tocb.getMessage() != null) {
      builder.setMessage(tocb.getMessage());
    }
    return builder.build();
  }

  public static KerberosCallback convert(
      IdentityServiceProtocolProtos.KerberosCallbackProto proto) {
    KerberosCallback kbCallback = null;
    if (proto.hasKrb5ServPrincipal()) {
      kbCallback = new KerberosCallback(proto.getKrb5ServPrincipal());
    } else {
      kbCallback = new KerberosCallback();
    }
    if (proto.hasTicket()) {
      kbCallback.setTicket(proto.getTicket().toByteArray());
    }

    return kbCallback;
  }

  public static IdentityServiceProtocolProtos.KerberosCallbackProto convert(
      KerberosCallback kbCb) {
    IdentityServiceProtocolProtos.KerberosCallbackProto.Builder builder =
        IdentityServiceProtocolProtos.KerberosCallbackProto.newBuilder();
    if (kbCb.getKrb5ServPrincipal() != null)
      builder.setKrb5ServPrincipal(kbCb.getKrb5ServPrincipal());
    if (kbCb.getTicket() != null) {
      builder.setTicket(ByteString.copyFrom(kbCb.getTicket()));
    }
    return builder.build();
  }

  public static SecretKey convert2SecretKey(TokenAuthProtos.KeyProto proto) throws
      InvalidKeyException {
    final String algorithm;
    final byte[] encode;
    if (proto.hasAlgorithm() && proto.hasEncoded()) {
      algorithm = proto.getAlgorithm();
      encode = proto.getEncoded().toByteArray();
    } else {
      throw new InvalidKeyException();
    }

    return new SecretKeySpec(encode, algorithm);
  }

  public static PublicKey convert2PublicKey(TokenAuthProtos.KeyProto proto) throws
      InvalidKeyException {
    final byte[] encode;
    if (proto.hasEncoded()) {
      encode = proto.getEncoded().toByteArray();
    } else {
      throw new InvalidKeyException();
    }

    return new DSAPublicKeyImpl(encode);
  }

  public static PrivateKey convert2PrivateKey(TokenAuthProtos.KeyProto proto) throws
      InvalidKeyException {
    final byte[] encode;
    if (proto.hasEncoded()) {
      encode = proto.getEncoded().toByteArray();
    } else {
      throw new InvalidKeyException();
    }

    return new DSAPrivateKey(encode);
  }

  public static TokenAuthProtos.KeyProto convert(Key key) {
    TokenAuthProtos.KeyProto.Builder builder =
        TokenAuthProtos.KeyProto.newBuilder();
    builder.setAlgorithm(key.getAlgorithm());
    builder.setFormat(key.getFormat());
    builder.setEncoded(ByteString.copyFrom(key.getEncoded()));
    return builder.build();
  }

  public static IdentityRequest convert(
      IdentityServiceProtocolProtos.RequestProto proto) {
    String sessionId = null;
    Callback[] callbacks = null;
    if (proto.hasSessionId()) {
      sessionId = proto.getSessionId();
    }
    if (proto.hasCallbacks()) {
      callbacks = convert(proto.getCallbacks());
    }
    boolean needSecrets = proto.getNeedSecrets();
    IdentityRequest request =
        new IdentityRequest(sessionId, callbacks, needSecrets);
    return request;
  }

  public static IdentityServiceProtocolProtos.RequestProto convert(
      IdentityRequest request) throws
      UnsupportedCallbackException {
    IdentityServiceProtocolProtos.RequestProto.Builder builder =
        IdentityServiceProtocolProtos.RequestProto.newBuilder();
    if (request.getSessionId() != null) {
      builder.setSessionId(request.getSessionId());
    }
    if (request.getCallbacks() != null) {
      builder.setCallbacks(convert(request.getCallbacks()));
    }
    builder.setNeedSecrets(request.needSecrets());
    return builder.build();
  }
  
  public static byte[] convert(
      IdentityServiceProtocolProtos.RenewTokenResponseProto proto) {
    return proto.getIdentityToken().toByteArray();
  }

  public static IdentityResponse convert(
      IdentityServiceProtocolProtos.ResponseProto proto) throws
      InvalidKeyException {
    String sessionId;
    Callback[] callbacks;
    int result = 0;
    String failure = "";
    if (proto.hasSessionId()) {
      sessionId = proto.getSessionId();
    } else {
      throw new NullPointerException();
    }
    if (proto.hasRequiredCallbacks()) {
      callbacks = convert(proto.getRequiredCallbacks());
    } else {
      callbacks = null;
    }
    if (proto.hasFailureCause()) {
      failure = proto.getFailureCause();
    }
    if (proto.hasResultCode()) {
      result = proto.getResultCode();
    }
    IdentityResponse response;
    if (proto.hasIdentityToken()) {
      byte[] identityToken = proto.getIdentityToken().toByteArray();
      SecretKey secretKey = proto.hasSecretKey() ? 
          convert2SecretKey(proto.getSecretKey()) : null;
      PublicKey publicKey = proto.hasPublicKey() ? 
          convert2PublicKey(proto.getPublicKey()) : null;
      response = new IdentityResponse(sessionId, result, failure,
          callbacks, identityToken, secretKey, publicKey);
    } else {
      response = new IdentityResponse(sessionId, result, failure,
          callbacks);
    }
    return response;
  }
  
  public static IdentityServiceProtocolProtos.RenewTokenResponseProto convert(
      byte[] identityToken) {
    IdentityServiceProtocolProtos.RenewTokenResponseProto.Builder builder = 
        IdentityServiceProtocolProtos.RenewTokenResponseProto.newBuilder();
    if(identityToken != null) {
      builder.setIdentityToken(ByteString.copyFrom(identityToken));
    }
    return builder.build();
  }

  public static IdentityServiceProtocolProtos.ResponseProto convert(
      IdentityResponse response) throws
      UnsupportedCallbackException {
    IdentityServiceProtocolProtos.ResponseProto.Builder builder =
        IdentityServiceProtocolProtos.ResponseProto.newBuilder();
    if (response.getSessionId() != null) {
      builder.setSessionId(response.getSessionId());
    }
    if (response.getSecretKey() != null) {
      builder.setSecretKey(convert(response.getSecretKey()));
    }
    if (response.getIdentityToken() != null) {
      builder.setIdentityToken(ByteString.copyFrom(response.getIdentityToken()));
    }
    builder.setResultCode(response.getResultCode());
    if (response.getFailure() != null) {
      builder.setFailureCause(response.getFailure());
    }
    if (response.getPublicKey() != null) {
      builder.setPublicKey(convert(response.getPublicKey()));
    }
    if (response.getRequiredCallbacks() != null) {
      builder.setRequiredCallbacks(convert(response.getRequiredCallbacks()));
    }
    return builder.build();
  }

  public static byte[] convertAccessTokenRequest(
      AuthorizationServiceProtocolProtos.GetAccessTokenRequestProto proto) {
    if (proto.hasIdentityToken()) {
      return proto.getIdentityToken().toByteArray();
    }
    return null;
  }

  public static AuthorizationServiceProtocolProtos.GetAccessTokenRequestProto convertAccessTokenRequest(
      byte[] identityToken, String protocol) {
    AuthorizationServiceProtocolProtos.GetAccessTokenRequestProto.Builder builder =
        AuthorizationServiceProtocolProtos.GetAccessTokenRequestProto.newBuilder();
    if (identityToken != null) {
      builder.setIdentityToken(ByteString.copyFrom(identityToken));
    }
    if (protocol != null) {
      builder.setProtocol(protocol);
    }
    return builder.build();
  }

  public static byte[] convertAccessToken(
      AuthorizationServiceProtocolProtos.GetAccessTokenResponseProto proto) {
    if (proto.hasAccessToken()) {
      return proto.getAccessToken().toByteArray();
    }
    return null;
  }

  public static AuthorizationServiceProtocolProtos.GetAccessTokenResponseProto convertAccessToken(
      byte[] accessToken) {
    AuthorizationServiceProtocolProtos.GetAccessTokenResponseProto.Builder builder =
        AuthorizationServiceProtocolProtos.GetAccessTokenResponseProto.newBuilder();
    if (accessToken != null) {
      builder.setAccessToken(ByteString.copyFrom(accessToken));
    }
    return builder.build();
  }
}
