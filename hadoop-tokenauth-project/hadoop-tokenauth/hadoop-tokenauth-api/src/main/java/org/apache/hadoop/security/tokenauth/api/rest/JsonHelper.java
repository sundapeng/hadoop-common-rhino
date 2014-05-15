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
package org.apache.hadoop.security.tokenauth.api.rest;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.io.StringWriter;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.TextInputCallback;
import javax.security.auth.callback.TextOutputCallback;
import javax.security.sasl.RealmCallback;

import org.apache.hadoop.security.tokenauth.api.IdentityRequest;
import org.apache.hadoop.security.tokenauth.api.IdentityResponse;
import org.apache.hadoop.security.tokenauth.kerberos.KerberosCallback;
import org.apache.hadoop.security.tokenauth.secrets.Secrets;
import org.apache.hadoop.security.tokenauth.token.TokenUtils;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.JSONValue;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import sun.security.provider.DSAPrivateKey;
import sun.security.provider.DSAPublicKeyImpl;

@SuppressWarnings("unchecked")
public class JsonHelper {

  public static final Log LOG = LogFactory.getLog(JsonHelper.class);

  // IdentityRequest and IdentityResponse
  public static final String SESSION_ID = "sessionId";
  public static final String NEED_SECRETS = "needSecrets";
  public static final String RESULT_CODE = "resultCode";
  public static final String FAILURE_CAUSE = "failureCause";
  public static final String IDENTITY_TOKEN = "identityToken";

  // Access token
  public static final String ACCESS_TOKEN = "accessToken";

  // Callbacks
  public static final String CALLBACKS = "callbacks";
  public static final String CALLBACK_TYPE = "type";
  public static final String CALLBACK_CONTENT = "content";

  public static final String NAME_CALLBACK = "name";
  public static final String NAME_CALLBACK_PROMPT = "prompt";
  public static final String NAME_CALLBACK_DEFAULTNAME = "defaultName";
  public static final String NAME_CALLBACK_INPUTNAME = "inputName";

  public static final String PASSWORD_CALLBACK = "password";
  public static final String PASSWORD_CALLBACK_PROMPT = "prompt";
  public static final String PASSWORD_CALLBACK_ECHO_ON = "echoOn";
  public static final String PASSWORD_CALLBACK_INPUTPASSWORD = "inputPassword";

  public static final String REALM_CALLBACK = "realm";
  public static final String REALM_CALLBACK_PROMPT = "prompt";
  public static final String REALM_CALLBACK_DEFAULTTEXT = "defaultText";
  public static final String REALM_CALLBACK_INPUTTEXT = "inputText";

  public static final String TEXT_INPUT_CALLBACK = "textinput";
  public static final String TEXT_INPUT_CALLBACK_PROMPT = "prompt";
  public static final String TEXT_INPUT_CALLBACK_DEFAULTTEXT = "defaultText";
  public static final String TEXT_INPUT_CALLBACK_INPUTTEXT = "inputText";

  public static final String TEXT_OUTPUT_CALLBACK = "textoutput";
  public static final String TEXT_OUTPUT_CALLBACK_MESSAGETYPE = "messageType";
  public static final String TEXT_OUTPUT_CALLBACK_MESSAGE = "message";

  public static final String KERBEROS_CALLBACK = "kerberos";
  public static final String KERBEROS_CALLBACK_KRB5SERVPRINCIPAL =
      "krb5ServPrincipal";
  public static final String KERBEROS_CALLBACK_TICKET = "ticket";

  // Key
  public static final String SECRETKEY = "secretKey";
  public static final String PUBLICKEY = "publicKey";
  public static final String PRIVATEKEY = "privateKey";

  public static final String ALGORITHM = "algorithm";
  public static final String ENCODE = "encode";
  public static final String FORMAT = "format";

  public static String toJsonString(final String key, final Object value) {
    JSONObject obj = new JSONObject();
    obj.put(key, value);
    return obj.toJSONString();
  }

  public static String toJsonString(IdentityRequest identityRequest) {
    JSONObject obj = new JSONObject();
    if (identityRequest == null) throw new NullPointerException();
    if (identityRequest.getSessionId() != null) {
      obj.put(SESSION_ID, identityRequest.getSessionId());
    }
    obj.put(NEED_SECRETS, identityRequest.needSecrets());
    if (identityRequest.getCallbacks() != null) {
      obj.put(CALLBACKS, toJsonString(identityRequest.getCallbacks()));
    }
    LOG.debug("IdentityRequest toJsonString sessionId " + identityRequest
        .getSessionId());
    return obj.toJSONString();
  }

  public static IdentityRequest toIdentityRequest(String jsonString) throws
      IOException {
    try {
      JSONObject object = getJsonObject(jsonString);

      String sessionId = null;
      Callback[] callbacks = null;
      boolean needSecrets = false;
      if (object.get(SESSION_ID) != null) {
        sessionId = (String) object.get(SESSION_ID);
      }
      if (object.get(CALLBACKS) != null) {
        callbacks = toCallbacks((JSONArray) object.get(CALLBACKS));
      }
      if (object.get(NEED_SECRETS) != null) {
        needSecrets = (Boolean) object.get(NEED_SECRETS);
      }
      IdentityRequest request =
          new IdentityRequest(sessionId, callbacks, needSecrets);
      LOG.debug("IdentityRequest toIdentityRequest sessionId " + request
          .getSessionId());
      return request;
    } catch (ParseException e) {
      throw new IOException(e);
    }
  }

  public static byte[] toAccessTokenBytes(String jsonString) throws IOException{
    try{
      JSONObject object=getJsonObject(jsonString);
      if(null!=object.get(ACCESS_TOKEN)){
        return TokenUtils.decodeToken((String)object.get(ACCESS_TOKEN));
      }
      else{
        throw null;
      }
    }
    catch(ParseException e){
      throw new IOException(e);
    }
  }

  public static String toJsonString(IdentityResponse identityResponse) {
    if (identityResponse == null) {
      throw new NullPointerException();
    }
    LOG.debug("IdentityResponse toJsonString sessionId " + identityResponse
        .getSessionId());
    JSONObject obj = new JSONObject();
    if (identityResponse.getSessionId() != null) {
      obj.put(SESSION_ID, identityResponse.getSessionId());
    }
    if (identityResponse.getFailure() != null) {
      obj.put(FAILURE_CAUSE, identityResponse.getFailure());
    }
    if (identityResponse.getIdentityToken() != null) {
      obj.put(IDENTITY_TOKEN,
          TokenUtils.encodeToken(identityResponse.getIdentityToken()));
    }
    if (identityResponse.getPublicKey() != null) {
      obj.put(PUBLICKEY, toJsonString(identityResponse.getPublicKey()));
    }
    if (identityResponse.getSecretKey() != null) {
      obj.put(SECRETKEY, toJsonString(identityResponse.getSecretKey()));
    }
    if (identityResponse.getRequiredCallbacks() != null) {
      obj.put(CALLBACKS, toJsonString(identityResponse.getRequiredCallbacks()));
    }
    obj.put(RESULT_CODE, identityResponse.getResultCode() + "");
    return obj.toJSONString();
  }

  public static IdentityResponse toIdentityResponse(String jsonString) throws
      ParseException, InvalidKeyException, IOException {
    JSONObject obj = getJsonObject(jsonString);
    StringWriter out = new StringWriter();
    String sessionId = (String) obj.get(SESSION_ID);
    int resultCode = Integer.valueOf((String) obj.get(RESULT_CODE));
    String failureCause = (String) obj.get(FAILURE_CAUSE);
    Callback[] requiredCallbacks = null;
    if (obj.get(CALLBACKS) != null) {
      requiredCallbacks = toCallbacks((JSONArray) obj.get(CALLBACKS));
    }

    byte[] identityToken = null;
    if (obj.get(IDENTITY_TOKEN) != null) {
      identityToken = TokenUtils.decodeToken((String) obj.get(IDENTITY_TOKEN));
    }
    SecretKey secretKey = null;
    if (obj.get(SECRETKEY) != null) {
      out.getBuffer().setLength(0);
      ((JSONObject)obj.get(SECRETKEY)).writeJSONString(out);
      secretKey = toSecretKey(out.toString());
    }
    PublicKey publicKey = null;
    if (obj.get(PUBLICKEY) != null) {
      out.getBuffer().setLength(0);
      ((JSONObject)obj.get(PUBLICKEY)).writeJSONString(out);
      publicKey = toPublicKey(out.toString());
    }
    IdentityResponse response =
        new IdentityResponse(sessionId, resultCode, failureCause,
            requiredCallbacks, identityToken, secretKey, publicKey);

    LOG.debug("IdentityResponse toIdentityResponse sessionId " + response
        .getSessionId());
    return response;
  }

  public static String toJsonString(Secrets secrets) {
    JSONObject jsonObject = new JSONObject();
    if (secrets == null) {
      throw new NullPointerException();
    }
    if (secrets.getPrivateKey() != null) {
      jsonObject.put(PRIVATEKEY, toJsonString(secrets.getPrivateKey()));
    }
    if (secrets.getPublicKey() != null) {
      jsonObject.put(PUBLICKEY, toJsonString(secrets.getPublicKey()));
    }
    if (secrets.getSecretKey() != null) {
      jsonObject.put(SECRETKEY, toJsonString(secrets.getSecretKey()));
    }
    return jsonObject.toJSONString();
  }

  public static Secrets toSecrets(String jsonString) throws ParseException,
      InvalidKeyException {
    JSONObject jsonObject = getJsonObject(jsonString);
    PublicKey publicKey = null;
    PrivateKey privateKey = null;
    SecretKey secretKey = null;
    JSONObject keyObject = null;
    try {
      if (jsonObject.get(PUBLICKEY) != null) {
        keyObject = (JSONObject)JSONValue.parse(jsonObject.get(PUBLICKEY).toString());
        publicKey = toPublicKey( keyObject.toJSONString());
      }
      if (jsonObject.get(PRIVATEKEY) != null) {
        keyObject = (JSONObject)JSONValue.parse(jsonObject.get(PRIVATEKEY).toString());
        privateKey = toPrivateKey( keyObject.toJSONString());
      }
      if (jsonObject.get(SECRETKEY) != null) {
        keyObject = (JSONObject)JSONValue.parse(jsonObject.get(SECRETKEY).toString());
        secretKey = toSecretKey( keyObject.toJSONString());
      }
    } catch (Exception e) {
      e.printStackTrace();
    }
    final SecretKey finalSecretKey = secretKey;
    final PublicKey finalPublicKey = publicKey;
    final PrivateKey finalPrivateKey = privateKey;
    return new Secrets() {
      @Override
      public SecretKey getSecretKey() {
        return finalSecretKey;
      }

      @Override
      public PublicKey getPublicKey() {
        return finalPublicKey;
      }

      @Override
      public PrivateKey getPrivateKey() {
        return finalPrivateKey;
      }
    };
  }

  public static PublicKey toPublicKey(final String jsonString) throws
      ParseException, InvalidKeyException {
    JSONObject jsonObject = getJsonObject(jsonString);
    String encode = (String) jsonObject.get(ENCODE);
    return new DSAPublicKeyImpl(TokenUtils.decodeToken(encode));
  }

  public static SecretKey toSecretKey(String jsonString) throws ParseException {
    JSONObject jsonObject = getJsonObject(jsonString);
    String algorithm = (String) jsonObject.get(ALGORITHM);
    String encode = (String) jsonObject.get(ENCODE);
    return new SecretKeySpec(TokenUtils.decodeToken(encode), algorithm);
  }

  public static PrivateKey toPrivateKey(String jsonString) throws ParseException,
      InvalidKeyException {
    JSONObject jsonObject = getJsonObject(jsonString);
    String encode = (String) jsonObject.get(ENCODE);
    return new DSAPrivateKey(TokenUtils.decodeToken(encode));
  }

  public static JSONObject toJsonString(Key key) {
    JSONObject jsonObject = new JSONObject();
    jsonObject
        .put(ENCODE, TokenUtils.encodeToken(key.getEncoded()));
    jsonObject.put(ALGORITHM, key.getAlgorithm());
    jsonObject.put(FORMAT, key.getFormat());
    return jsonObject;
  }

  public static Callback[] toCallbacks(JSONArray jsonArray) throws
      ParseException {
    List<Callback> callbacks = new ArrayList<Callback>();
    for (Object obj : jsonArray) {
      try {
        JSONObject jsonObject = (JSONObject) obj;
        String type = (String) jsonObject.get(CALLBACK_TYPE);
        String content =
            ((JSONObject) jsonObject.get(CALLBACK_CONTENT)).toJSONString();
        if (content != null) {
          if (NAME_CALLBACK.equals(type)) {
            callbacks.add(toNameCallback(content));
          }
          if (PASSWORD_CALLBACK.equals(type)) {
            callbacks.add(toPasswordCallback(content));
          }
          if (KERBEROS_CALLBACK.equals(type)) {
            callbacks.add(toKerberosCallback(content));
          }
          if (REALM_CALLBACK.equals(type)) {
            callbacks.add(toRealmCallback(content));
          }
          if (TEXT_INPUT_CALLBACK.equals(type)) {
            callbacks.add(toTextInputCallback(content));
          }
          if (TEXT_OUTPUT_CALLBACK.equals(type)) {
            callbacks.add(toTextOutputCallback(content));
          }
        }
      } catch (Exception e) {
        e.printStackTrace();
      }
    }
    return callbacks.toArray(new Callback[callbacks.size()]);
  }

  public static JSONArray toJsonString(Callback[] callbacks) {
    JSONArray array = new JSONArray();
    for (Callback cb : callbacks) {
      if (cb instanceof NameCallback) {
        JSONObject obj = new JSONObject();
        obj.put(CALLBACK_TYPE, NAME_CALLBACK);
        obj.put(CALLBACK_CONTENT, toJsonString((NameCallback) cb));
        array.add(obj);
      }
      if (cb instanceof PasswordCallback) {
        JSONObject obj = new JSONObject();
        obj.put(CALLBACK_TYPE, PASSWORD_CALLBACK);
        obj.put(CALLBACK_CONTENT, toJsonString((PasswordCallback) cb));
        array.add(obj);
      }
      if (cb instanceof TextInputCallback) {
        JSONObject obj = new JSONObject();
        obj.put(CALLBACK_TYPE, TEXT_INPUT_CALLBACK);
        obj.put(CALLBACK_CONTENT, toJsonString((TextInputCallback) cb));
        array.add(obj);
      }
      if (cb instanceof TextOutputCallback) {
        JSONObject obj = new JSONObject();
        obj.put(CALLBACK_TYPE, TEXT_OUTPUT_CALLBACK);
        obj.put(CALLBACK_CONTENT, toJsonString((TextOutputCallback) cb));
        array.add(obj);
      }
      if (cb instanceof RealmCallback) {
        JSONObject obj = new JSONObject();
        obj.put(CALLBACK_TYPE, REALM_CALLBACK);
        obj.put(CALLBACK_CONTENT, toJsonString((RealmCallback) cb));
        array.add(obj);
      }
      if (cb instanceof KerberosCallback) {
        JSONObject obj = new JSONObject();
        obj.put(CALLBACK_TYPE, NAME_CALLBACK);
        obj.put(CALLBACK_CONTENT, toJsonString((KerberosCallback) cb));
        array.add(obj);
      }
    }
    return array;
  }

  public static NameCallback toNameCallback(String jsonString) throws
      ParseException {
    JSONObject jsonObject = getJsonObject(jsonString);
    NameCallback nameCb;
    if (jsonObject.get(NAME_CALLBACK_DEFAULTNAME) != null) {
      nameCb = new NameCallback((String) jsonObject.get(NAME_CALLBACK_PROMPT),
          (String) jsonObject.get(NAME_CALLBACK_DEFAULTNAME));
    } else {
      nameCb = new NameCallback((String) jsonObject.get(NAME_CALLBACK_PROMPT));
    }
    if (jsonObject.get(NAME_CALLBACK_INPUTNAME) != null) {
      nameCb.setName((String) jsonObject.get(NAME_CALLBACK_INPUTNAME));
    }
    return nameCb;
  }

  public static JSONObject toJsonString(NameCallback nameCb) {
    if (nameCb == null) {
      throw new NullPointerException();
    }
    JSONObject jsonObject = new JSONObject();
    jsonObject.put(NAME_CALLBACK_PROMPT, nameCb.getPrompt());
    if (nameCb.getDefaultName() != null) {
      jsonObject.put(NAME_CALLBACK_DEFAULTNAME, nameCb.getDefaultName());
    }
    if (nameCb.getName() != null) {
      jsonObject.put(NAME_CALLBACK_INPUTNAME, nameCb.getName());
    }
    return jsonObject;
  }

  public static PasswordCallback toPasswordCallback(String jsonString) throws
      ParseException {
    JSONObject jsonObject = getJsonObject(jsonString);
    PasswordCallback pwCb;
    if (jsonObject.get(PASSWORD_CALLBACK_ECHO_ON) != null) {
      pwCb =
          new PasswordCallback((String) jsonObject.get(PASSWORD_CALLBACK_PROMPT),
              (Boolean) jsonObject.get(PASSWORD_CALLBACK_ECHO_ON));
    } else {
      pwCb =
          new PasswordCallback((String) jsonObject.get(PASSWORD_CALLBACK_PROMPT),
              false);
    }
    if (jsonObject.get(PASSWORD_CALLBACK_INPUTPASSWORD) != null) {
      pwCb.setPassword(((String) jsonObject.get(PASSWORD_CALLBACK_INPUTPASSWORD))
          .toCharArray());
    }
    return pwCb;
  }

  public static JSONObject toJsonString(PasswordCallback pwCb) {
    if (pwCb == null) {
      throw new NullPointerException();
    }
    JSONObject jsonObject = new JSONObject();
    jsonObject.put(PASSWORD_CALLBACK_PROMPT, pwCb.getPrompt());
    if (pwCb.isEchoOn()) {
      jsonObject.put(PASSWORD_CALLBACK_ECHO_ON, true);
    }
    if (pwCb.getPassword() != null) {
      jsonObject.put(PASSWORD_CALLBACK_INPUTPASSWORD,
          String.valueOf(pwCb.getPassword()));
    }
    return jsonObject;
  }

  public static RealmCallback toRealmCallback(String jsonString) throws
      ParseException {
    JSONObject jsonObject = getJsonObject(jsonString);
    RealmCallback realmCb;
    if (jsonObject.get(REALM_CALLBACK_DEFAULTTEXT) != null) {
      realmCb = new RealmCallback((String) jsonObject.get(REALM_CALLBACK_PROMPT),
          (String) jsonObject.get(REALM_CALLBACK_DEFAULTTEXT));
    } else {
      realmCb = new RealmCallback((String) jsonObject.get(REALM_CALLBACK_PROMPT));
    }
    if (jsonObject.get(REALM_CALLBACK_INPUTTEXT) != null) {
      realmCb.setText((String) jsonObject.get(REALM_CALLBACK_INPUTTEXT));
    }
    return realmCb;
  }

  public static JSONObject toJsonString(RealmCallback realmCb) {
    if (realmCb == null) {
      throw new NullPointerException();
    }
    JSONObject jsonObject = new JSONObject();
    jsonObject.put(REALM_CALLBACK_PROMPT, realmCb.getPrompt());
    if (realmCb.getDefaultText() != null) {
      jsonObject.put(REALM_CALLBACK_DEFAULTTEXT, realmCb.getDefaultText());
    }
    if (realmCb.getText() != null) {
      jsonObject.put(REALM_CALLBACK_INPUTTEXT, realmCb.getText());
    }
    return jsonObject;
  }

  public static TextInputCallback toTextInputCallback(String jsonString) throws
      ParseException {
    JSONObject jsonObject = getJsonObject(jsonString);
    TextInputCallback textInputCb;
    if (jsonObject.get(TEXT_INPUT_CALLBACK_DEFAULTTEXT) != null) {
      textInputCb =
          new TextInputCallback((String) jsonObject.get(
              TEXT_INPUT_CALLBACK_PROMPT),
              (String) jsonObject.get(TEXT_INPUT_CALLBACK_DEFAULTTEXT));
    } else {
      textInputCb = new TextInputCallback(
          (String) jsonObject.get(TEXT_INPUT_CALLBACK_PROMPT));
    }
    if (jsonObject.get(TEXT_INPUT_CALLBACK_INPUTTEXT) != null) {
      textInputCb.setText((String) jsonObject.get(REALM_CALLBACK_INPUTTEXT));
    }
    return textInputCb;
  }

  public static JSONObject toJsonString(TextInputCallback textInputCb) {
    if (textInputCb == null) {
      throw new NullPointerException();
    }
    JSONObject jsonObject = new JSONObject();
    jsonObject.put(TEXT_INPUT_CALLBACK_PROMPT, textInputCb.getPrompt());
    if (textInputCb.getDefaultText() != null) {
      jsonObject.put(TEXT_INPUT_CALLBACK_DEFAULTTEXT, textInputCb.getDefaultText());
    }
    if (textInputCb.getText() != null) {
      jsonObject.put(TEXT_INPUT_CALLBACK_INPUTTEXT, textInputCb.getText());
    }
    return jsonObject;
  }

  public static TextOutputCallback toTextOutputCallback(String jsonString) throws
      ParseException {
    JSONObject jsonObject = getJsonObject(jsonString);
    TextOutputCallback textOutputCb = new TextOutputCallback(
        Integer.valueOf((String) jsonObject.get(TEXT_OUTPUT_CALLBACK_MESSAGETYPE)),
        (String) jsonObject.get(TEXT_OUTPUT_CALLBACK_MESSAGE));
    return textOutputCb;
  }

  public static JSONObject toJsonString(TextOutputCallback textOutputCb) {
    if (textOutputCb == null) {
      throw new NullPointerException();
    }
    JSONObject jsonObject = new JSONObject();
    jsonObject
        .put(TEXT_OUTPUT_CALLBACK_MESSAGETYPE, textOutputCb.getMessageType() + "");
    jsonObject.put(TEXT_OUTPUT_CALLBACK_MESSAGE, textOutputCb.getMessage());
    return jsonObject;
  }

  public static KerberosCallback toKerberosCallback(String jsonString) throws
      ParseException {
    JSONObject jsonObject = getJsonObject(jsonString);
    KerberosCallback kerberosCb;
    String krb5ServPrincipal =
        (String) jsonObject.get(KERBEROS_CALLBACK_KRB5SERVPRINCIPAL);
    String ticket = (String) jsonObject.get(KERBEROS_CALLBACK_TICKET);
    if (krb5ServPrincipal != null) {
      kerberosCb = new KerberosCallback(krb5ServPrincipal);
    } else {
      kerberosCb = new KerberosCallback();
    }
    if (ticket != null) {
      kerberosCb.setTicket(TokenUtils.decodeToken(ticket));
    }
    return kerberosCb;
  }

  public static JSONObject toJsonString(KerberosCallback kerberosCallback) {
    if (kerberosCallback == null) {
      throw new NullPointerException();
    }
    JSONObject jsonObject = new JSONObject();
    if (kerberosCallback.getKrb5ServPrincipal() != null) {
      jsonObject.put(KERBEROS_CALLBACK_KRB5SERVPRINCIPAL,
          kerberosCallback.getKrb5ServPrincipal());
    }
    if (kerberosCallback.getTicket() != null) {
      jsonObject.put(KERBEROS_CALLBACK_TICKET,
          TokenUtils.encodeToken(kerberosCallback.getTicket()));
    }
    return jsonObject;
  }

  private static JSONObject getJsonObject(String jsonString) throws
      ParseException {
    JSONParser parser = new JSONParser();
    JSONObject obj = (JSONObject) parser.parse(jsonString);
    return obj;
  }

  public static void main(String[] args) throws Exception {
    System.out.println(JsonHelper.toJsonString("msg", 123));
  }

}
