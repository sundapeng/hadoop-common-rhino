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
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.Principal;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import org.apache.hadoop.security.tokenauth.DataInputBuffer;
import org.apache.hadoop.security.tokenauth.DataOutputBuffer;
import org.apache.hadoop.security.tokenauth.secrets.Secrets;
import org.apache.hadoop.security.tokenauth.token.Attribute;
import org.apache.hadoop.security.tokenauth.token.Token;
import org.apache.hadoop.security.tokenauth.token.TokenPrincipal;
import org.apache.hadoop.security.tokenauth.util.SecurityUtils;
import org.apache.hadoop.security.tokenauth.util.WritableUtils;

/**
 * Token's structure is as following
 * |--------------------------------------------------------------------------------------------------------------------|
 * | headers  |  issuer | subject | instant | not before | not on or after | audiences | attributes | ....   | signature|
 * |--------------------------------------------------------------------------------------------------------------------|
 * | headers  |                  public fields                                         |  private fields     | signature|
 * 
 * Signature is calculated on the whole token.
 * 
 */
public abstract class AbstractToken implements Token{
  private long id;
  private String issuer;
  private String user;
  private long issueInstant;
  private long notBefore;
  private long notOnOrAfter;
  private List<String> audiences;
  private List<Attribute> attributes;
  
  private boolean encrypted = false;
  private Secrets secrets; /** secrets are used to build trust of token **/
  private final byte[] rawBytes;
  
  /* Create a token with a specified token ID */
  public AbstractToken(long id, Secrets secrets,
      String issuer, String user, long issueInstant, 
      long notBefore, long notOnOrAfter, boolean encrypted){
    if(user == null || secrets == null || issuer == null)
      throw new NullPointerException("secrets, issuer and user can not be null.");
    if(0==id){
      this.id=(new SecureRandom()).nextLong();
    }
    else{
      this.id=id;
    }
    this.secrets = secrets;
    this.issuer = issuer;
    this.user = user;
    this.issueInstant = issueInstant;
    this.notBefore = notBefore;
    this.notOnOrAfter = notOnOrAfter;
    this.encrypted = encrypted;
    this.rawBytes = null;
  }
  
  /* Create a token with a random token ID */
  public AbstractToken(Secrets secrets,
      String issuer, String user, long issueInstant, 
      long notBefore, long notOnOrAfter, boolean encrypted) {
    this(0,secrets,issuer,user,issueInstant,notBefore,notOnOrAfter,encrypted);
  }
  
  /*only for read*/
  public AbstractToken(byte[] rawBytes) {
    if(rawBytes == null)
      throw new NullPointerException("rawBytes can not be null.");
    this.secrets = null;
    this.rawBytes = new byte[rawBytes.length];
    System.arraycopy(rawBytes, 0, this.rawBytes, 0, rawBytes.length);
  }
  
  /*only for read and verification*/
  public AbstractToken(byte[] rawBytes, Secrets secrets) {
    this(rawBytes);
    this.secrets = secrets;
  }

  @Override
  public void write(DataOutput out) throws IOException {
    if(secrets == null || secrets.getPrivateKey() == null) {
      if(rawBytes == null) throw new NullPointerException(
          "Token raw Bytes can not be null.");
      else {out.write(rawBytes); return;}
    }
    DataOutputBuffer buffer = new DataOutputBuffer();
    writeHeaderFields(buffer);
    writePublicFields(buffer);
    if(encrypted) {
      /* do encryption */
    } else {
      writePrivateFields(buffer);
    }
    
    byte[] signature;
    try {
      signature = SecurityUtils.generateSignature(getSecrets()
          .getPrivateKey(), buffer.getData(), 0, buffer.getLength());
    } catch (Exception e) {
      throw new IOException("Generate token signature failed.");
    }
    
    WritableUtils.writeBytes(out, buffer.getData(), 0, buffer.getLength());
    WritableUtils.writeBytes(out, signature, 0, signature.length);
  }
  
  /**
   * Write headers.
   */
  abstract void writeHeaderFields(DataOutput out) throws IOException;
  
  void writePublicFields(DataOutput out) throws IOException {
    WritableUtils.writeVLong(out, id);
    WritableUtils.writeString(out, issuer);
    WritableUtils.writeString(out, user);
    WritableUtils.writeVLong(out, issueInstant);
    WritableUtils.writeVLong(out, notBefore);
    WritableUtils.writeVLong(out, notOnOrAfter);
    int size = audiences != null ? audiences.size() : 0;
    WritableUtils.writeVInt(out, size);
    if(size > 0) {
      for(int i=0; i < size; i++) {
        WritableUtils.writeString(out, audiences.get(i));
      }
    }
  }
  
  void writePrivateFields(DataOutput out) throws IOException {
    int size = attributes != null ? attributes.size() : 0;
    WritableUtils.writeVInt(out, size);
    if(size > 0)
      writeAttributes(out, attributes);
  }
  
  /**
   * Write attributes
   */
  private void writeAttributes(DataOutput out, List<Attribute> 
      attributes) throws IOException {
    DataOutputBuffer buffer = new DataOutputBuffer();
    ObjectOutputStream objectOutputStream = new ObjectOutputStream(buffer);
    objectOutputStream.writeObject(attributes);
    WritableUtils.writeBytes(out, buffer.getData(), 0, buffer.getLength());
  }
  
  @SuppressWarnings("unchecked")
  private List<Attribute> readAttributes(DataInput in) throws IOException {
    byte[] attributesObj = WritableUtils.readBytes(in);
    DataInputBuffer buffer = new DataInputBuffer();
    buffer.reset(attributesObj, 0, attributesObj.length);
    ObjectInputStream objectInputStream = new ObjectInputStream(buffer);
    
    try {
      return (List<Attribute>)objectInputStream.readObject();
    } catch (ClassNotFoundException e) {
      throw new IOException(e);
    }
  }

  @Override
  public void readFields(DataInput in) throws IOException {
    byte[] fields = WritableUtils.readBytes(in);
    byte[] signature = WritableUtils.readBytes(in);
    
    if(secrets != null) {
      try {
        SecurityUtils.verifySignature(getSecrets()
            .getPublicKey(), fields, 0, fields.length, signature);
      } catch (Exception e) {
        throw new IOException("Verify token signature failed.");
      }
    }
    
    DataInputBuffer buffer = new DataInputBuffer();
    buffer.reset(fields, 0, fields.length);
    readHeaderFields(buffer);
    readPublicFields(buffer);
    if(encrypted && secrets != null) {
      /* do decryption */
    } else {
      readPrivateFields(buffer);
    }
  }
  
  void setEncrypted(boolean encrypted) {
    this.encrypted = encrypted;
  }
  
  /**
   * Read headers
   */
  abstract void readHeaderFields(DataInput in) throws IOException;
  
  void readPublicFields(DataInput in) throws IOException {
    id = WritableUtils.readVLong(in);
    issuer = WritableUtils.readString(in);
    user = WritableUtils.readString(in);
    issueInstant = WritableUtils.readVLong(in);
    notBefore = WritableUtils.readVLong(in);
    notOnOrAfter = WritableUtils.readVLong(in);
    int size = WritableUtils.readVInt(in);
    if(size > 0) {
      audiences = new ArrayList<String>();
      for(int i=0; i < size; i++) {
        audiences.add(WritableUtils.readString(in));
      }
    }
  }
  
  protected void readPrivateFields(DataInput in) throws IOException {
    int size = WritableUtils.readVInt(in);
    if(size > 0)
      attributes = readAttributes(in);
  }
  
  @Override
  public Principal getPrincipal() {
    return new TokenPrincipal(user);
  }
  
  protected Secrets getSecrets() {
    return secrets;
  }

  @Override
  public long getId() {
    return id;
  }

  @Override
  public long getCreationTime() {
    return issueInstant;
  }

  @Override
  public long getExpiryTime() {
    return notOnOrAfter;
  }

  public String getIssuer() {
    return issuer;
  }

  public long getIssueInstant() {
    return issueInstant;
  }
  
  public String getUser(){
    return user;
  }

  public long getNotBefore() {
    return notBefore;
  }

  public long getNotOnOrAfter() {
    return notOnOrAfter;
  }
  
  public boolean isEncrypted() {
    return encrypted;
  }

  public List<String> getAudiences() {
    if(audiences == null)
      audiences = new ArrayList<String>();
    return audiences;
  }

  @Override
  public List<Attribute> getAttributes() {
    if(attributes == null)
      attributes = new ArrayList<Attribute>();
    return attributes;
  }
  
  static class InvalidToken extends IOException {
    private static final long serialVersionUID = 2703854435814134824L;

    public InvalidToken(String msg) { 
      super(msg);
    }
  }
}
