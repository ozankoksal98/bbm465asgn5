import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

// Alice
public class Client {
  private static Socket socket;
  private static DataInputStream dis;
  private static DataOutputStream dos;
  private static Cipher cipher;
  private static String userpass, serverToConnect = "mail";
  private static PrivateKey privKey;
  private static SecretKey sessionKey;

  public static void main(String[] args) {
    try {
      cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
      byte[] hashedPassword = Files.readAllBytes(new File("passwd").toPath());
      Scanner sc = new Scanner(System.in);
      System.out.println("Enter password");
      while (!verifyPassword(sc.nextLine(), hashedPassword)) {
        System.out.println("Enter password");
      }
      sc.close();
    } catch (Exception e) {
      e.printStackTrace();
    }
    connect(3000);
    System.out.println(new Date().toString());
    getSessionKey();

  }

  private static void getSessionKey() {
    // Send message 1
    String clientName = "Alice";
    try {
      BufferedReader reader = new BufferedReader(new FileReader("cert/kdc.cer"));
      String[] certFileContent = new String(Files.readAllBytes(Paths.get("cert/kdc.cer"))).split("\n", 2);
      byte[] signatureBytes = Base64.getDecoder().decode(certFileContent[0].getBytes());
      byte[] certBytes = certFileContent[1].getBytes();
      X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
          .generateCertificate(new ByteArrayInputStream(certBytes));
      PublicKey pk = certificate.getPublicKey();
      Signature sig = Signature.getInstance("SHA1WithRSA");
      sig.initVerify(pk);
      sig.update(certBytes);
      if (sig.verify(signatureBytes)) {
        // First part of the first message , client name 
        dos.writeInt(clientName.getBytes().length);
        dos.write(clientName.getBytes());
        // Second part of the first message that will be encrypted.
        Date timeStampOne = new Date();
        String secondPart = clientName + "," + userpass + "," + serverToConnect + "," + timeStampOne.toString();
        byte[] encryptedContent = encrypt(secondPart.getBytes(), pk);
        System.out.println(new String(Base64.getEncoder().encode(encryptedContent)));
        dos.writeInt(encryptedContent.length);
        dos.write(encryptedContent);


        int firstPartLength = dis.readInt();
        byte[] firstPartBytes = new byte[firstPartLength];
        dis.readFully(firstPartBytes);
        int ticketLength = dis.readInt();
        byte[] ticketBytes = new byte[ticketLength];
        dis.readFully(ticketBytes);
        FileInputStream fis = new FileInputStream("keystore/client.jks");
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(fis, "password".toCharArray());
        privKey = (PrivateKey) keystore.getKey("client", "password".toCharArray());
        String[] firstPartDecrypted = new String( decrypt(firstPartBytes, privKey)).split(",");
        sessionKey = new SecretKeySpec(Base64.getDecoder().decode(firstPartDecrypted[0]), "AES");
        
      }

    } catch (Exception ex) {
      ex.printStackTrace();
    }
  }

  private static byte[] encrypt(byte[] content, Key key) throws Exception {
    cipher.init(1, key);
    return cipher.doFinal(content);
  }

  private static byte[] decrypt(byte[] content, Key key) throws Exception {
    cipher.init(2, key);
    return cipher.doFinal(content);
  }

  private static void connect(int portNumber) {
    try {
      socket = new Socket("localhost", portNumber);
      dis = new DataInputStream(socket.getInputStream());
      dos = new DataOutputStream(socket.getOutputStream());
      System.out.println("Connected to " + portNumber);

      Thread t = new Thread(() -> {
        System.out.println("running");
      });
      t.start();
    } catch (Exception e) {
      System.out.println("Couldnt connect!");
      e.printStackTrace();
    }

  }

  // verify password by comparing hashes
  private static boolean verifyPassword(String password, byte[] hashedPassword) {
    try {
      MessageDigest md = MessageDigest.getInstance("SHA-1");
      md.update(password.getBytes());
      byte[] passwordDigest = md.digest();
      byte[] decodedHash = Base64.getDecoder().decode(hashedPassword);

      if (Arrays.equals(decodedHash, passwordDigest)) {
        userpass = password;
        return true;
      } else {
        return false;
      }
    } catch (Exception e) {
      e.printStackTrace();
    }
    return false;
  }
}
