package org.apache.hadoop.security.tokenauth.has.identity;

import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;

import org.apache.hadoop.security.tokenauth.DataInputBuffer;
import org.apache.hadoop.security.tokenauth.DataOutputBuffer;
import org.apache.hadoop.security.tokenauth.Writable;
import org.apache.hadoop.security.tokenauth.token.impl.IdentityToken;
import org.apache.hadoop.security.tokenauth.util.WritableUtils;

public class IdentityTokenInfo implements Writable, Serializable {
  private long id;
  private String user;
  private long creationTime;
  private long expirationTime;
  private boolean revoked;
  private IdentityToken token;

  public IdentityTokenInfo(IdentityToken token) {
    this.id = token.getId();
    this.user = token.getUser();
    this.creationTime = token.getCreationTime();
    this.expirationTime = token.getExpiryTime();
    this.revoked = false;
    this.token = token;
  }

  public long getId() {
    return id;
  }

  public String getUser() {
    return user;
  }

  public long getCreationTime() {
    return creationTime;
  }

  public long getExpirationTime() {
    return expirationTime;
  }

  public IdentityToken getToken() {
    return token;
  }

  public void revoke() {
    revoked = true;
  }

  public boolean isRevoked() {
    return revoked;
  }

  @Override
  public void write(DataOutput out) throws IOException {
    DataOutputBuffer buffer = new DataOutputBuffer();
    WritableUtils.writeVLong(buffer, id);
    WritableUtils.writeString(buffer, user);
    WritableUtils.writeVLong(buffer, creationTime);
    WritableUtils.writeVLong(buffer, expirationTime);
    WritableUtils.writeVInt(buffer, revoked ? 1 : 0);
    DataOutputBuffer tokenBuffer = new DataOutputBuffer();
    token.write(tokenBuffer);
    WritableUtils.writeBytes(buffer, tokenBuffer.getData(), 0, tokenBuffer.getLength());
    WritableUtils.writeBytes(out, buffer.getData(), 0, buffer.getLength());
  }

  @Override
  public void readFields(DataInput in) throws IOException {
    byte[] tokenInfoByte = WritableUtils.readBytes(in);
    DataInputBuffer buffer = new DataInputBuffer();
    buffer.reset(tokenInfoByte, 0, tokenInfoByte.length);
    id = WritableUtils.readVLong(buffer);
    user = WritableUtils.readString(buffer);
    creationTime = WritableUtils.readVLong(buffer);
    expirationTime = WritableUtils.readVLong(buffer);
    revoked = (WritableUtils.readVInt(buffer) == 1);
    byte[] tokenByte = WritableUtils.readBytes(buffer);
    DataInputBuffer tokenBuffer = new DataInputBuffer();
    tokenBuffer.reset(tokenByte, 0, tokenByte.length);
    token = new IdentityToken(tokenByte);
    token.readFields(tokenBuffer);
  }

  private void writeObject(ObjectOutputStream out) throws IOException {
    write(out);
  }

  private void readObject(ObjectInputStream in) throws IOException {
    readFields(in);
  }
}
