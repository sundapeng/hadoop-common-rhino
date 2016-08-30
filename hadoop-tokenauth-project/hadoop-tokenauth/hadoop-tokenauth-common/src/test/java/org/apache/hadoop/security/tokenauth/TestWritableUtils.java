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

package org.apache.hadoop.security.tokenauth;

import static org.junit.Assert.*;

import org.apache.hadoop.security.tokenauth.util.WritableUtils;
import org.junit.Test;


public class TestWritableUtils {
  private final static String testString = "hello tokenauth";
  private final static byte[] testBytes = testString.getBytes();
  
  @Test
  public void testWriteString() throws Exception {
    DataOutputBuffer outBuffer = new DataOutputBuffer(1024);
    WritableUtils.writeString(outBuffer, testString);
    
    DataInputBuffer inputBuffer = new DataInputBuffer();
    inputBuffer.reset(outBuffer.getData(), 0, outBuffer.getLength());
    
    String result = WritableUtils.readString(inputBuffer);
    
    assertEquals(result, testString);
    
    outBuffer.close();
    inputBuffer.close();
  }
  
  @Test
  public void testWriteBytes() throws Exception {
    DataOutputBuffer outBuffer = new DataOutputBuffer(1024);
    WritableUtils.writeBytes(outBuffer, testBytes, 0, testBytes.length);
    
    DataInputBuffer inputBuffer = new DataInputBuffer();
    inputBuffer.reset(outBuffer.getData(), 0, outBuffer.getLength());
    
    byte[] result = WritableUtils.readBytes(inputBuffer);
    
    assertEquals(result.length, testBytes.length);
    assertEquals(new String(result, 0, result.length), 
        new String(testBytes, 0, testBytes.length));
    
    outBuffer.close();
    inputBuffer.close();
  }
  
  @Test
  public void testWriteVLong() throws Exception {
    final long testLong = 1234567890;
    DataOutputBuffer outBuffer = new DataOutputBuffer(1024);
    WritableUtils.writeVLong(outBuffer, testLong);
    
    DataInputBuffer inputBuffer = new DataInputBuffer();
    inputBuffer.reset(outBuffer.getData(), 0, outBuffer.getLength());
    
    long result = WritableUtils.readVLong(inputBuffer);
    
    assertEquals(result, testLong);
    
    outBuffer.close();
    inputBuffer.close();
  }
  
  @Test
  public void testWriteVInt() throws Exception {
    final int testInt = 123;
    DataOutputBuffer outBuffer = new DataOutputBuffer(1024);
    WritableUtils.writeVInt(outBuffer, testInt);
    
    DataInputBuffer inputBuffer = new DataInputBuffer();
    inputBuffer.reset(outBuffer.getData(), 0, outBuffer.getLength());
    
    long result = WritableUtils.readVInt(inputBuffer);
    
    assertEquals(result, testInt);
    
    outBuffer.close();
    inputBuffer.close();
  }
  
  @Test
  public void testWrite() throws Exception {
    final int testInt = 123;
    final long testLong = 1234567890;
    DataOutputBuffer outBuffer = new DataOutputBuffer(1024);
    WritableUtils.writeVLong(outBuffer, testLong);
    WritableUtils.writeVInt(outBuffer, testInt);
    WritableUtils.writeBytes(outBuffer, testBytes, 0, testBytes.length);
    WritableUtils.writeString(outBuffer, testString);
    
    DataInputBuffer inputBuffer = new DataInputBuffer();
    inputBuffer.reset(outBuffer.getData(), 0, outBuffer.getLength());
    
    long resultLong = WritableUtils.readVLong(inputBuffer);
    int resultInt = WritableUtils.readVInt(inputBuffer);
    byte[] resultBytes = WritableUtils.readBytes(inputBuffer);
    String resultString = WritableUtils.readString(inputBuffer);
    
    assertEquals(resultLong, testLong);
    assertEquals(resultInt, testInt);
    assertEquals(resultBytes.length, testBytes.length);
    assertEquals(new String(resultBytes, 0, resultBytes.length), 
        new String(testBytes, 0, testBytes.length));
    assertEquals(resultString, testString);
    
    outBuffer.close();
    inputBuffer.close();
  }
  
}
