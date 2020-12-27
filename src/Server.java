import java.io.DataInput;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
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

public class Server {
  private static String serverType;
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
    System.out.println(args[0]);
    try {
      ServerSocket serverSocket = new ServerSocket(portNumber);
      System.out.println("Listening on " + serverSocket.getLocalPort());
      FileInputStream fis = new FileInputStream("keystore/" + args[0] + ".jks");
      KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
      keystore.load(fis, "password".toCharArray());
      privKey = (PrivateKey) keystore.getKey(args[0], "password".toCharArray());
      Thread reception = new Thread(() -> {
        Thread.currentThread();
        while (!Thread.interrupted()) {
          try {
            Socket client = serverSocket.accept();
            DataInputStream dis = new DataInputStream(client.getInputStream());
            DataOutputStream dos = new DataOutputStream(client.getOutputStream());
            byte[] clientNameBytes = new byte[dis.readInt()];
            dis.readFully(clientNameBytes);
            byte[] ticket = new byte[dis.readInt()];
            dis.readFully(ticket);
            byte[] encryptedNonce = new byte[dis.readInt()];
            dis.readFully(encryptedNonce);
            clientName = new String(clientNameBytes);
            System.out.println(new String(clientName));
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            String[] ticketContents = new String(decrypt(ticket, privKey)).split(",");
            System.out.println(ticketContents[0] + ticketContents[1] + ticketContents[2] + ticketContents[3]);
            byte[] keyBytes = Base64.getDecoder().decode(ticketContents[3]);
            SecretKey sessionKey = new SecretKeySpec(keyBytes, "AES");
            cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            int nonce = new BigInteger(decrypt(encryptedNonce, sessionKey)).intValue();
            int nonceTwo = ThreadLocalRandom.current().nextInt();
            String messageFour = String.valueOf((nonce+1)) +","+ String.valueOf(nonceTwo);
            byte[] messsageFourEncrypted = encrypt(messageFour.getBytes(), sessionKey);
            dos.writeInt(messsageFourEncrypted.length);
            dos.write(messsageFourEncrypted);
            System.out.println(nonce+","+nonceTwo);
            byte[] messageFive = new byte[dis.readInt()];
            dis.readFully(messageFive);
            System.out.println("recieved nonce: "+new BigInteger(decrypt(messageFive, sessionKey)).intValue());
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
      sc.close();
      serverSocket.close();
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
