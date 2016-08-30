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
package org.apache.hadoop.security.tokenauth.secrets;

import static org.junit.Assert.assertEquals;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.tokenauth.has.HASConfiguration;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import sun.security.x509.AlgorithmId;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateIssuerName;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateSubjectName;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

public class TestSecretsSerializer {
  private static Configuration conf;
  private static final String KEY_ALIAS = "test";
  private static final String KEY_ALIAS2 = "test2";
  private static final String SECRET_ENTRY_PREF="sec";
  private static final String PRIVATEKEY_ENTRY_PREF="pri";
  private static File keystoreFile;
  private static File keyFile;
  private static KeyStore keystore;
  private static SecretKey secretKey;
  private static PublicKey publicKey;
  private static PrivateKey privateKey;
  private static char[] password = "password".toCharArray();
  
  @BeforeClass
  public static void setUp() throws Exception {
    conf = new HASConfiguration();
    conf.set(HASConfiguration.
        HADOOP_SECURITY_TOKENAUTH_SECRETSMANAGER_KEYSTORE_KEY, "/tmp/tokenauth.keystore");
    conf.set(HASConfiguration.
        HADOOP_SECURITY_TOKENAUTH_SECRETSMANAGER_KEYSTORE_SECRET_KEY, "/tmp/tokenauth.keystore.key");
    
    keystoreFile = new File("/tmp/tokenauth.keystore");
    FileOutputStream fkeystoreOut = new FileOutputStream(keystoreFile);
    
    keyFile = new File("/tmp/tokenauth.keystore.key");
    FileOutputStream fkeyOut = new FileOutputStream(keyFile);
    fkeyOut.write("password".getBytes());
    fkeyOut.close();
    
    keystore = KeyStore.getInstance("jceks");
    keystore.load(null, password);
    keystore.store(fkeystoreOut, password);
    
    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
    keyGen.init(128);
    secretKey = keyGen.generateKey();
    
    KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DSA");
    SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
    keyPairGen.initialize(512, random);
    KeyPair keyPair = keyPairGen.generateKeyPair();
    publicKey = keyPair.getPublic();
    privateKey = keyPair.getPrivate();
    
    Certificate certificate = generateCertificate(privateKey, publicKey, KEY_ALIAS);
    Certificate[] certChain = new Certificate[1];
    certChain[0] = certificate;
    keystore.setKeyEntry(PRIVATEKEY_ENTRY_PREF + KEY_ALIAS, privateKey, password, certChain);
    KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(secretKey);
    keystore.setEntry(SECRET_ENTRY_PREF + KEY_ALIAS, secretKeyEntry,
        new KeyStore.PasswordProtection(password));
    
    FileOutputStream fout = new FileOutputStream(keystoreFile);
    keystore.store(fout, password);
    
  }
  
  @AfterClass
  public static void tearDown() throws Exception {
    if (keystoreFile != null) {
      keystoreFile.delete();
    }
    if (keyFile != null) {
      keyFile.delete();
    }
  }
  
  @Test
  public void testLoadSecretsMap() throws Exception {
    SecretsSerializer serializer = new KeyStoreSecretsSerializer(conf);
    Map<String, Secrets> secretsMap = new HashMap<String, Secrets>();
    serializer.loadSecretsMap(secretsMap);
    Secrets secrets = secretsMap.get(KEY_ALIAS);
    SecretKey loadSecretKey = secrets.getSecretKey();
    PrivateKey loadPrivateKey = secrets.getPrivateKey();
    
    assertEquals(new String(loadSecretKey.getEncoded(), 0, loadSecretKey.getEncoded().length), 
        new String(secretKey.getEncoded(), 0, secretKey.getEncoded().length));
    assertEquals(new String(loadPrivateKey.getEncoded(), 0, loadPrivateKey.getEncoded().length), 
        new String(privateKey.getEncoded(), 0, privateKey.getEncoded().length));
  }
  
  @Test
  public void testSerializeSecrets() throws Exception {
    Secrets secrets = SecretsManager.get().getSecrets(KEY_ALIAS2);
    SecretsSerializer serializer = new KeyStoreSecretsSerializer(conf);
    serializer.serializeSecrets(KEY_ALIAS2, secrets);
  }
  
  @Test
  public void testDeleteSecrets() throws Exception {
    SecretsSerializer serializer = new KeyStoreSecretsSerializer(conf);
    serializer.deleteSecrets(KEY_ALIAS);
  }
  
  private static Certificate generateCertificate(PrivateKey priKey, PublicKey pubKey,
      String name) throws CertificateException, IOException, NoSuchProviderException,
      NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    X509CertInfo info = new X509CertInfo();
    Date from = new Date();
    Date to = new Date(from.getTime() + 365 * 86400000l);
    CertificateValidity interval = new CertificateValidity(from, to);
    BigInteger sn = new BigInteger(64, new SecureRandom());
    X500Name owner = new X500Name("CN=" + name);
    info.set(X509CertInfo.VALIDITY, interval);
    info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(sn));
    info.set(X509CertInfo.SUBJECT, new CertificateSubjectName(owner));
    info.set(X509CertInfo.ISSUER, new CertificateIssuerName(owner));
    info.set(X509CertInfo.KEY, new CertificateX509Key(pubKey));
    info.set(X509CertInfo.VERSION,
        new CertificateVersion(CertificateVersion.V3));
    AlgorithmId algo = new AlgorithmId(AlgorithmId.sha1WithDSA_oid);
    info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algo));
    X509CertImpl cert = new X509CertImpl(info);
    cert.sign(priKey, algo.getName());
    return cert;
  }

}
