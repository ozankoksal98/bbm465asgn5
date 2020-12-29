import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.Scanner;
import java.util.concurrent.ThreadLocalRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Can be run as :
 * $ java Server <serverType>
 * serverType => Mail | Web | Database
 */
public class Server {
  private static String serverName;
  private static int portNumber;
  private static Cipher cipher;
  private static String clientName;
  private static PrivateKey privKey;

  public static void main(String[] args) {
    if (args[0].equals("Mail")) {
      portNumber = 3001;
    } else if (args[0].equals("Web")) {
      portNumber = 3002;
    } else {
      portNumber = 3003;
    }
    serverName = args[0];
    try {
      BufferedWriter log = new BufferedWriter(new FileWriter(serverName.toLowerCase() + "ServerLog"));
      ServerSocket serverSocket = new ServerSocket(portNumber);
      System.out.println("------" + serverName + " server started listening on port number "
          + serverSocket.getLocalPort() + "------");
      log.write("------" + serverName + " server started listening on port number " + serverSocket.getLocalPort()
          + "------\n");
      // Reading the private key of the server
      FileInputStream fis = new FileInputStream("keystore/" + args[0] + ".jks");
      KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
      keystore.load(fis, "password".toCharArray());
      privKey = (PrivateKey) keystore.getKey(args[0], "password".toCharArray());
      Thread reception = new Thread(() -> {
        Thread.currentThread();
        while (!Thread.interrupted()) {
          try {
            Socket client = serverSocket.accept();
            log.write("New client connected.\n");
            DataInputStream dis = new DataInputStream(client.getInputStream());
            DataOutputStream dos = new DataOutputStream(client.getOutputStream());
            // Reading the third message
            byte[] clientNameBytes = new byte[dis.readInt()];
            dis.readFully(clientNameBytes);
            byte[] ticket = new byte[dis.readInt()];
            dis.readFully(ticket);
            byte[] encryptedNonce = new byte[dis.readInt()];
            dis.readFully(encryptedNonce);
            log.write("3) Third message recieved.\n");
            clientName = new String(clientNameBytes);
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            String[] ticketContents = new String(decrypt(ticket, privKey)).split(",");
            log.write("3) Ticket decrypted with " + serverName + " server's private key.\n");
            log.write("3) Session key in Base64 : " + ticketContents[3] + "\n");
            // Since the key is an array of bytes, the keys is sent in Base64 format
            byte[] keyBytes = Base64.getDecoder().decode(ticketContents[3]);
            SecretKey sessionKey = new SecretKeySpec(keyBytes, "AES");
            cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            // The line below N1
            int nonce = new BigInteger(decrypt(encryptedNonce, sessionKey)).intValue();
            log.write("3) Recieved nonce value decrypted (N1) : " + nonce + "\n");
            log.write(String.format("3) Third message contents : %s, P%s(%s, %s, %s, %s), KA(%d)\n", clientName,
                serverName, ticketContents[0], ticketContents[1], ticketContents[2], ticketContents[3], nonce));
            int nonceTwo = ThreadLocalRandom.current().nextInt();
            String messageFour = String.valueOf((nonce + 1)) + "," + String.valueOf(nonceTwo);
            // Creating and sending message four
            log.write("4) Created nonce value N2 : " + nonceTwo + "\n");
            byte[] messsageFourEncrypted = encrypt(messageFour.getBytes(), sessionKey);
            log.write(String.format("4) Message four contents : KA(%d, %d)\n", nonce + 1, nonceTwo));
            dos.writeInt(messsageFourEncrypted.length);
            dos.write(messsageFourEncrypted);
            log.write("4) Message four sent.\n");
            // Recieving message five
            byte[] messageFive = new byte[dis.readInt()];
            dis.readFully(messageFive);
            log.write("5) Message five recieved.\n");
            log.write(("5) Message five decrypted with session key.\n"));
            byte[] messageFiveDecrypted = decrypt(messageFive, sessionKey);
            int recievedNonceTwo = new BigInteger(messageFiveDecrypted).intValue();
            log.write(String.format("5) Message five content : KA(%d)",recievedNonceTwo));
            if (recievedNonceTwo == nonceTwo + 1) {
              log.write(
                  String.format("5) Recieved nonce %d matches the created nonce %d +1", recievedNonceTwo, nonceTwo));
            } else {
              log.write(String.format("5) Recieved nonce %d DOES NOT match the created nonce %d +1", recievedNonceTwo,
                  nonceTwo));
            }
            log.flush();
          } catch (SocketException se) {

          } catch (Exception ex) {
            ex.printStackTrace();
          }
        }
      });
      reception.start();

      // Current thread listens for command line inputs
      Scanner sc = new Scanner(System.in);
      String close;
      while (true) {
        close = sc.nextLine();
        if (close.equals("close")) {
          break;
        }
      }
      // Close remaining threads sockets etc.
      reception.interrupt();
      log.close();
      sc.close();
      serverSocket.close();
      log.close();

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
}
