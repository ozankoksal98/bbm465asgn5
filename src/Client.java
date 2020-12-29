import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
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

public class Client {
  private static Socket socket;
  private static DataInputStream dis;
  private static DataOutputStream dos;
  private static Cipher cipher;
  private static String userpass, serverToConnect;
  private static PrivateKey privKey;
  private static SecretKey sessionKey;
  private static String clientName = "Alice";
  private static byte[] ticket;
  private static BufferedWriter log;
  private static String password;

  public static void main(String[] args) {
    try {
      log = new BufferedWriter(new FileWriter("clientLog"));
      // Password created by kdc
      byte[] hashedPassword = Files.readAllBytes(new File("passwd").toPath());
      Scanner sc = new Scanner(System.in);
      System.out.println("Enter password");
      while (true) {
        password = sc.nextLine();
        if (!verifyPassword(password, hashedPassword)) {
          System.out.println("Enter password");
          log.write(String.format("Wrong password entered at %s.\n", new Date().toString()));
          log.flush();
        } else {
          log.write(String.format("Correct password entered at %s.\n", new Date().toString()));
          log.flush();
          break;
        }
      }
      System.out.println("Which server do you want to establish a connection to ? (Mail, Web, Database)");
      serverToConnect = sc.nextLine();
      log.write("Client has chosen to establish connection to the " + serverToConnect + " server.\n");
      sc.close();
    } catch (Exception e) {
      e.printStackTrace();
    }
    try {
      // Connect to KDC server get the session key.
      getSessionKey();
      // Establish connection to chosen server and get authorization.
      connectToServer(serverToConnect);
      log.close();
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
      log.write("Connected to KDC server on port 3000.\n");
      cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
      // Reading the certificate file and extracting the signature and certificate.
      String[] certFileContent = new String(Files.readAllBytes(Paths.get("cert/kdc.cer"))).split("\n", 2);
      byte[] signatureBytes = Base64.getDecoder().decode(certFileContent[0].getBytes());
      byte[] certBytes = certFileContent[1].getBytes();
      X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
          .generateCertificate(new ByteArrayInputStream(certBytes));
      log.write("Reading certificate and extracting public key of KDC server.\n");
      log.write("KDC certificate signature in Base64: " + certFileContent[0] + "\n");
      PublicKey pk = certificate.getPublicKey();
      Signature sig = Signature.getInstance("SHA1WithRSA");
      sig.initVerify(pk);
      sig.update(certBytes);
      // Verifying the signature.
      if (sig.verify(signatureBytes)) {
        log.write("Signature verified.\n");
        // First part of the first message , client name
        dos.writeInt(clientName.getBytes().length);
        dos.write(clientName.getBytes());
        // Second part of the first message that will be encrypted.
        Date timeStampOne = new Date();
        // Second part of the first message PKDC(...)
        String secondPart = clientName + "," + userpass + "," + serverToConnect + "," + timeStampOne.toString();
        byte[] encryptedContent = encrypt(secondPart.getBytes(), pk);
        log.write("1) Second part of the first message encrypted with KDC`s public key.\n");
        log.write(String.format("1) First message content : %s, PKDC(%s, %s ,%s, %s)\n", clientName, clientName,
            password, serverToConnect, timeStampOne.toString()));
        dos.writeInt(encryptedContent.length);
        dos.write(encryptedContent);
        log.write("1) First message sent.\n");
        // Recieving the second message
        // First part of the second message PA(Client, serverToConnect, sessionKey)
        byte[] firstPartBytes = new byte[dis.readInt()];
        dis.readFully(firstPartBytes);
        ticket = new byte[dis.readInt()];
        dis.readFully(ticket);
        log.write("2) Second message recieved.\n");
        // Reading the private key of the client from the keystore
        FileInputStream fis = new FileInputStream("keystore/client.jks");
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(fis, "password".toCharArray());
        privKey = (PrivateKey) keystore.getKey("client", "password".toCharArray());
        String[] firstPart = new String(decrypt(firstPartBytes, privKey)).split(",");
        log.write("2) First part of the second message decrypted with the private key of client.\n");
        sessionKey = new SecretKeySpec(Base64.getDecoder().decode(firstPart[0]), "AES");
        log.write(String.format("2) Second message content: PA(%s, %s, %s), Ticket\n", firstPart[0], firstPart[1],
            firstPart[2]));
        log.flush();
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
    if (serverName.equals("Mail")) {
      portNumber = 3001;
    } else if (serverName.equals("Web")) {
      portNumber = 3002;
    } else {
      portNumber = 3003;
    }
    connect(portNumber);
    log.write("Connected to " + serverName + " server on port " + portNumber + ".\n");
    // Create the nonce N1
    int nonce = ThreadLocalRandom.current().nextInt();
    cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
    byte[] encryptedNonce = encrypt(BigInteger.valueOf(nonce).toByteArray(), sessionKey);
    log.write("3) Created nonce N1 : " + nonce + " -> encrypted -> "
        + Base64.getEncoder().encodeToString(encryptedNonce) + " (encoded to Base64)\n");
    log.write(String.format("3) Third message content : %s, Ticket, KA(%d)\n", clientName, nonce));
    log.write("3) Third message sent.\n");
    // Send third message
    dos.writeInt(clientName.length());
    dos.write(clientName.getBytes());
    dos.writeInt(ticket.length);
    dos.write(ticket);
    dos.writeInt(encryptedNonce.length);
    dos.write(encryptedNonce);
    // Recieve fourth message
    byte[] messageFour = new byte[dis.readInt()];
    dis.readFully(messageFour);
    log.write("4) Message four recieved and decrypted with session key(KA).\n");
    String[] messageFourSplit = new String(decrypt(messageFour, sessionKey)).split(",");
    // receivedNonce = N1 + 1
    int receivedNonce = Integer.parseInt(messageFourSplit[0]);
    // Checking if recieved nonce is correct
    if (receivedNonce == nonce + 1) {
      log.write(String.format("4) Received nonce %d matches created nonce %d +1\n", receivedNonce, nonce));
      int nonceTwo = Integer.parseInt(messageFourSplit[1]);
      log.write(String.format("4) Message four contents : KA(%d, %d)\n", receivedNonce, nonceTwo));
      byte[] messageFive = encrypt(BigInteger.valueOf(nonceTwo + 1).toByteArray(), sessionKey);
      log.write(String.format("5) Recieved nonce N2 created by %s server %d -> +1 -> %d -> encrypted -> %s (encoded to Base64)\n", serverName,
          nonceTwo, nonceTwo + 1, Base64.getEncoder().encodeToString(messageFive)));
      log.write(String.format("5) Message five content : PA(%s)\n",nonceTwo+1));
      // Sending fifth message
      dos.writeInt(messageFive.length);
      dos.write(messageFive);
      log.write("5) Message five sent.\n");
    } else {
      log.write(String.format("4) Received nonce %d DOES NOT match created nonce %d +1", receivedNonce, nonce));
    }
    disconnect();
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
    } catch (Exception e) {
      System.out.println("Couldnt connect!");
      e.printStackTrace();
    }
  }

  /**
   * Disconnects from the current socket connection nad unsets the input, output streams
   */
  private static void disconnect() {
    try {
      dis.close();
      dos.close();
      socket.close();
    } catch (Exception ex) {
      ex.printStackTrace();
    }
  }

  /**
   * Verifies the entered password by comparing the saved hash with the entered passwords hash.
   * @param password
   * @param hashedPassword
   * @return
   */
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
