package org.apache.hadoop.security.tokenauth.secrets;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.crypto.SecretKey;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.tokenauth.has.HASConfiguration;

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

class KeyStoreSecretsSerializer extends SecretsSerializer implements Runnable {
  public static final Log LOG = LogFactory.getLog(KeyStoreSecretsSerializer.class);
  
  private static final String SECRET_ENTRY_PREF="sec";
  private static final String PRIVATEKEY_ENTRY_PREF="pri";
  private static char[] DEFAULT_KS_PWD = "password".toCharArray();

  private String ksFile;
  private char[] ksPwd;
  private KeyStore keyStore;
  
  private List<SecretsEntry> toAddSecrets = new ArrayList<SecretsEntry>();
  private Set<String> toRemoveSecrets = new HashSet<String>();
  private List<SecretsEntry> addedSecrets = new ArrayList<SecretsEntry>();
  private Set<String> removedSecrets = new HashSet<String>();
  
  public KeyStoreSecretsSerializer() {
    Configuration conf = new HASConfiguration();
    initialize(conf);
  }
  
  public KeyStoreSecretsSerializer(Configuration conf) {
    initialize(conf);
  }
  
  void initialize(Configuration conf) {
    ksFile = conf.get(HASConfiguration.
        HADOOP_SECURITY_TOKENAUTH_SECRETSMANAGER_KEYSTORE_KEY);
    String secretFile = conf.get(HASConfiguration.
        HADOOP_SECURITY_TOKENAUTH_SECRETSMANAGER_KEYSTORE_SECRET_KEY);
    ksPwd = readPwd(secretFile);
    
    if (ksFile != null) {
      try {
        keyStore = initKeyStore(ksFile, ksPwd);
      } catch (Exception e) {
        LOG.error("Keystore init failed.", e);
        keyStore = null;
      }
    }
    
    if (keyStore != null) {
      LOG.info("Use keystore for secrets map.");
      
      Thread thread = new Thread(this);
      thread.setDaemon(true);
      thread.setName("Secrets serializer thread.");
      thread.start();
    } else {
      LOG.info("Do not use keystore for secrets map.");
    }
  }
  
  @Override
  public void loadSecretsMap(Map<String, Secrets> secretsMap) {
    if (keyStore != null) {
      try {
        loadKeyStore(secretsMap, keyStore, ksPwd);
      } catch (Exception e) {
        LOG.error("Failed to load secrets map from kestore.");
      }
    }
  }

  @Override
  public void serializeSecrets(String name, Secrets secrets) {
    if (keyStore != null) {
      synchronized (this) {
        toAddSecrets.add(new SecretsEntry(name, secrets));
      }
    }
  }

  @Override
  public void deleteSecrets(String name) {
    if (keyStore != null) {
      synchronized (this) {
        toRemoveSecrets.add(name);
      }
    }
  }
  
  private KeyStore initKeyStore(String ksFile, char[] ksPwd) 
      throws IOException, CertificateException
      , NoSuchAlgorithmException, KeyStoreException {
    
    KeyStore keyStore = KeyStore.getInstance("jceks");
    FileInputStream fis = null;
    FileOutputStream fos = null;
    try {
      fis = new FileInputStream(ksFile);
      keyStore.load(fis, ksPwd);
    } catch (IOException e) {
      LOG.warn(e.getMessage());
      
      keyStore.load(null, ksPwd);
      fos = new FileOutputStream(ksFile);
      keyStore.store(fos, ksPwd);
    } finally {
      if (fis != null) {
        fis.close();
      }
      if (fos != null) {
        fos.close();
      }
    }
    return keyStore;
  }

  private char[] readPwd(String path) {
    if (path != null && !path.isEmpty()) {
      File file = new File(path);
      if (file.exists()) {
        BufferedReader reader = null;
        try {
          reader = new BufferedReader(new FileReader(file));
          return reader.readLine().toCharArray();
        } catch (IOException e) {
          LOG.warn("Secret file read failed." + path);
        } finally {
          if (reader != null) {
            try {
              reader.close();
            } catch (IOException e) {
            }
          }
        }
      }
    }
    
    return DEFAULT_KS_PWD;
  }

  private void loadKeyStore(Map<String, Secrets> secretsMap,
      final KeyStore keyStore, final char[] ksPwd) throws Exception {
    Enumeration<String> alias = keyStore.aliases();
    while (alias.hasMoreElements()) {
      String aliasName = alias.nextElement();
      try {
        if (aliasName.startsWith(PRIVATEKEY_ENTRY_PREF) && keyStore.isKeyEntry(aliasName)) {
          String secretName = aliasName.replace(PRIVATEKEY_ENTRY_PREF, SECRET_ENTRY_PREF);
          Secrets secrets = new SecretsImpl((SecretKey) keyStore.getKey(secretName, ksPwd), 
              keyStore.getCertificate(aliasName).getPublicKey(), (PrivateKey) keyStore.getKey(aliasName, ksPwd));
          
          String name =
              aliasName.substring(PRIVATEKEY_ENTRY_PREF.length()).toLowerCase();
          secretsMap.put(name, secrets);
        }
      } catch (Exception e) {
        LOG.warn("Load keystore failed.", e);
        throw e;
      }
    }
  }
  
  @Override 
  public void run() {
    if (keyStore == null) {
      return;
    }
    while (true) {
      try {
        Thread.sleep(5 * 60 * 1000);
      } catch (InterruptedException e1) {
        LOG.warn("Terminating secrets serializer thread");
      }
      synchronized (this) {
        if (toAddSecrets.size()>0) {
          addedSecrets.clear();
          addedSecrets.addAll(toAddSecrets);
          toAddSecrets.clear();
        }
      }
      synchronized (this) {
        if (toRemoveSecrets.size()>0) {
          removedSecrets.clear();
          removedSecrets.addAll(toRemoveSecrets);
          toRemoveSecrets.clear();
        }
      }
      
      FileOutputStream fos = null;
      try {
        boolean update = false;
        for (SecretsEntry entry: addedSecrets) {
          addSecrets(entry.getName(), entry.getSecrets());
          update = true;
        }
        
        for (String removedKey : removedSecrets) {
          removeSecret(removedKey);
          update = true;
        }
        
        if (update) {
          fos = new FileOutputStream(ksFile);
          keyStore.store(fos, ksPwd);
        }
      } catch (Exception e) {
        LOG.error(e);
      } finally {
        if (fos != null) {
          try {
            fos.close();
          } catch (IOException e) {
          }
        }
      }
    }
  }
  
  private void removeSecret(String removedKey) {
    try {
      keyStore.deleteEntry(PRIVATEKEY_ENTRY_PREF+removedKey);
    } catch (KeyStoreException e) {
      LOG.error("remove " + removedKey + " PrivateKeyEntry failed",e);
    }
    try {
      keyStore.deleteEntry(SECRET_ENTRY_PREF+removedKey);
    } catch (KeyStoreException e) {
      LOG.error("remove " + removedKey + " SecretEntry failed",e);
    }
  }

  private void addSecrets(String aliasName, Secrets secrets) {
    Certificate certificate = null;
    try {
      certificate = generateCertificate(secrets.getPrivateKey(), secrets.getPublicKey(), aliasName);
      Certificate[] certChain = new Certificate[1];
      certChain[0] = certificate;
      KeyStore.SecretKeyEntry secretKeyEntry =
          new KeyStore.SecretKeyEntry(secrets.getSecretKey());
      keyStore.setKeyEntry(PRIVATEKEY_ENTRY_PREF + 
          aliasName, secrets.getPrivateKey(), ksPwd, certChain);
      keyStore.setEntry(SECRET_ENTRY_PREF + aliasName, secretKeyEntry,
          new KeyStore.PasswordProtection(ksPwd));
    } catch (Exception e) {
      LOG.error(e);
    }
  }

  private Certificate generateCertificate(PrivateKey priKey, PublicKey pubKey,
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

  static class SecretsEntry {

    private String name;
    private Secrets secrets;

    public SecretsEntry(String name, Secrets secrets) {
      this.name = name;
      this.secrets = secrets;
    }

    public String getName() {
      return name;
    }

    public Secrets getSecrets() {
      return secrets;
    }
  }
  
}
