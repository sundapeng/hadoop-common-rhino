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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

import org.junit.Test;


public class TestDataOutputBuffer {
  private final static byte[] tests = "hello tokenauth".getBytes();
  
  @Test
  public void testWrite() throws Exception {
    DataOutputBuffer outBuffer = new DataOutputBuffer(1024);
    outBuffer.write(tests);
    
    assertEquals(outBuffer.getLength(), tests.length);
    assertEquals(new String(outBuffer.getData(), 0, outBuffer.getLength()), 
        new String(tests, 0, tests.length));
    
    outBuffer.close();
    
  }
  
  @Test
  public void testRest() throws Exception {
    DataOutputBuffer outBuffer = new DataOutputBuffer(1024);
    outBuffer.write(tests);
    outBuffer.reset();
    
    assertEquals(outBuffer.getLength(), 0);
    
    outBuffer.close();
  }
  
  @Test
  public void testRead() throws Exception {
    DataOutputBuffer outBuffer = new DataOutputBuffer(1024);
    outBuffer.write(tests);
    
    DataInputBuffer inputBuffer = new DataInputBuffer();
    inputBuffer.reset(tests, 0, tests.length);
    byte[] result = new byte[1024];
    int n = inputBuffer.read(result);
    
    assertEquals(n, tests.length);
    assertEquals(new String(result, 0, n), 
        new String(tests, 0, tests.length));
    
    outBuffer.close();
    
  }
  
  @Test
  public void testWriteFromInput() throws Exception {
    DataInputBuffer inputBuffer = new DataInputBuffer();
    inputBuffer.reset(tests, 0, tests.length);
    
    DataOutputBuffer outBuffer = new DataOutputBuffer(1024);
    outBuffer.write(inputBuffer, inputBuffer.getLength());
    
    assertEquals(outBuffer.getLength(), tests.length);
    assertEquals(new String(outBuffer.getData(), 0, outBuffer.getLength()), 
        new String(tests, 0, tests.length));
    
    outBuffer.close();
    inputBuffer.close();
    
  }
  
  @Test
  public void testWrite2File() throws Exception {
    File file = new File("test.txt");
    FileOutputStream fout = new FileOutputStream(file);
    DataOutputBuffer outBuffer = new DataOutputBuffer(1024);
    outBuffer.write(tests);
    outBuffer.writeTo(fout);
    
    FileInputStream fin = new FileInputStream(file);
    byte[] result = new byte[1024];
    int n = fin.read(result);
    
    assertEquals(n, tests.length);
    assertEquals(new String(result, 0, n), 
        new String(tests, 0, tests.length));
    
   fout.close();
   outBuffer.close();
   fin.close();
   file.delete();
    
  }
  
  @Test
  public void testGetPosition() throws Exception {
    DataInputBuffer inputBuffer = new DataInputBuffer();
    inputBuffer.reset(tests, 0, tests.length);
    
    final int position = 2;
    int n = position;
    while (n-- > 0) {
      inputBuffer.readByte();
    }
    
    assertEquals(inputBuffer.getPosition(), position);
    
    inputBuffer.close();
    
  }

}
