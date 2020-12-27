import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.math.BigInteger;
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
import java.util.concurrent.ThreadLocalRandom;

// Alice
public class Client {
  private static Socket socket;
  private static DataInputStream dis;
  private static DataOutputStream dos;
  private static Cipher cipher;
  private static String userpass, serverToConnect = "Mail";
  private static PrivateKey privKey;
  private static SecretKey sessionKey;
  private static String clientName = "Alice";
  private static byte[] ticket;

  public static void main(String[] args) {
    try {
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
    try {
      System.out.println(new Date().toString());
      getSessionKey();
      connectToServer("mail");
    } catch (Exception ex) {
      ex.printStackTrace();
    }

  }

  /**
   * Starts a connection with the KDC server to get a session key to use in
   * communication with the server of their choice.
   */
  private static void getSessionKey() {
    // Connect to port 3000 which is the KDC server
    connect(3000);
    // Send message 1
    try {
      cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
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
        // Recieving the second message
        byte[] firstPartBytes = new byte[dis.readInt()];
        dis.readFully(firstPartBytes);
        ticket= new byte[dis.readInt()];
        dis.readFully(ticket);
        FileInputStream fis = new FileInputStream("keystore/client.jks");
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(fis, "password".toCharArray());
        privKey = (PrivateKey) keystore.getKey("client", "password".toCharArray());
        String[] firstPartDecrypted = new String(decrypt(firstPartBytes, privKey)).split(",");
        sessionKey = new SecretKeySpec(Base64.getDecoder().decode(firstPartDecrypted[0]), "AES");
        System.out.println("session key : "+firstPartDecrypted[0]);
      }

    } catch (Exception ex) {
      ex.printStackTrace();
    }
    disconnect();
  }

  /**
   * Starts a connection with the server of choice to share a key, identify itself
   * and authenticate.
   * 
   * @param serverName Name of the server that client wants to connect to "mail",
   *                   "web", "database".
   */
  private static void connectToServer(String serverName) throws Exception {
    int portNumber;
    if (serverName.equals("mail")) {
      portNumber = 3001;
    } else if (serverName.equals("web")) {
      portNumber = 3002;
    } else {
      portNumber = 3003;
    }
    System.out.println("Port number " + portNumber); // delete this last before submission
    connect(portNumber);
    // Calculate the nonce
    int nonce = ThreadLocalRandom.current().nextInt();
    cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
    System.out.println("nonce : " + nonce);
    byte[] encryptedNonce = encrypt(BigInteger.valueOf(nonce).toByteArray(), sessionKey);
    System.out.println("encrypted :" + Base64.getEncoder().encodeToString(encryptedNonce));
    dos.writeInt(clientName.length());
    dos.write(clientName.getBytes());
    dos.writeInt(ticket.length);
    dos.write(ticket);
    dos.writeInt(encryptedNonce.length);
    dos.write(encryptedNonce);
    System.out.println(Base64.getEncoder().encodeToString(ticket));
    byte[] messageFourEncrypted = new byte[dis.readInt()];
    dis.readFully(messageFourEncrypted);
    System.out.println(new String(decrypt(messageFourEncrypted, sessionKey)));
    String[] messageFourSplit = new String(decrypt(messageFourEncrypted, sessionKey)).split(",");
    int nonceTwo = Integer.parseInt(messageFourSplit[1]);
    byte[] messsageFive = encrypt(BigInteger.valueOf(nonceTwo+1).toByteArray(),sessionKey);
    dos.writeInt(messsageFive.length);
    dos.write(messsageFive);
  }

  private static byte[] encrypt(byte[] content, Key key) throws Exception {
    cipher.init(1, key);
    return cipher.doFinal(content);
  }

  private static byte[] decrypt(byte[] content, Key key) throws Exception {
    cipher.init(2, key);
    return cipher.doFinal(content);
  }

  /**
   * Starts a socket connection and sets instances of input and output streams.
   * 
   * @param portNumber Socket port number to connect to
   */
  private static void connect(int portNumber) {
    try {
      socket = new Socket("localhost", portNumber);
      dis = new DataInputStream(socket.getInputStream());
      dos = new DataOutputStream(socket.getOutputStream());
      System.out.println("Connected to " + portNumber);

    } catch (Exception e) {
      System.out.println("Couldnt connect!");
      e.printStackTrace();
    }
  }

  /**
   * Disconnects from the current socket connection
   */
  private static void disconnect() {
    try {
      System.out.println("disconnected");
      dis.close();
      dos.close();
      socket.close();
    } catch (Exception ex) {
      ex.printStackTrace();
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
