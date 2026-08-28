import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;

public class Server {

    public static void main(String[] args) {

        if (args.length != 1) {
            System.out.println("Usage: java Server <port>");
            return;
        }

        int port = Integer.parseInt(args[0]);

        try {
            ServerSocket serverSocket = new ServerSocket(port);
            System.out.println("Server started. Waiting for connections...");

            while (true) {

                Socket clientSocket = serverSocket.accept();

                try {
                    DataInputStream dis =
                            new DataInputStream(clientSocket.getInputStream());
                    DataOutputStream dos =
                            new DataOutputStream(clientSocket.getOutputStream());

                    // Receive userid
                    String userid = dis.readUTF();
                    System.out.println("User " + userid + " connected.");

                    // Receive encrypted AES key
                    int keyLength = dis.readInt();
                    byte[] encryptedAESKey = new byte[keyLength];
                    dis.readFully(encryptedAESKey);

                    // Receive signature
                    int sigLength = dis.readInt();
                    byte[] signatureBytes = new byte[sigLength];
                    dis.readFully(signatureBytes);

                    // Load user's public key (userid.pub)
                    byte[] pubKeyBytes =
                            Files.readAllBytes(Path.of(userid + ".pub"));

                    X509EncodedKeySpec pubSpec =
                            new X509EncodedKeySpec(pubKeyBytes);

                    KeyFactory kf = KeyFactory.getInstance("RSA");
                    PublicKey userPublicKey =
                            kf.generatePublic(pubSpec);

                    // Verify signature
                    Signature sig =
                            Signature.getInstance("SHA256withRSA");

                    sig.initVerify(userPublicKey);
                    sig.update(userid.getBytes("UTF8"));
                    sig.update(encryptedAESKey);

                    boolean verified =
                            sig.verify(signatureBytes);

                    if (!verified) {
                        System.out.println("Signature not verified.");
                        dos.writeInt(0);   // indicate failure
                        clientSocket.close();
                        continue;
                    }

                    System.out.println("Signature verified.");

                    // Load master private key (Base64 encoded)
                    String base64PrivateKey =
                            Files.readString(Path.of("server-b64.prv"));

                    byte[] decodedPrivateKey =
                            Base64.getMimeDecoder().decode(base64PrivateKey);

                    PKCS8EncodedKeySpec prvSpec =
                            new PKCS8EncodedKeySpec(decodedPrivateKey);

                    PrivateKey masterPrivateKey =
                            kf.generatePrivate(prvSpec);

                    // Decrypt AES key using RSA
                    Cipher cipher =
                            Cipher.getInstance("RSA/ECB/PKCS1Padding");

                    cipher.init(Cipher.DECRYPT_MODE, masterPrivateKey);

                    byte[] decryptedAESKey =
                            cipher.doFinal(encryptedAESKey);

                    System.out.println("AES key decrypted.");

                    // Send decrypted AES key back
                    dos.writeInt(decryptedAESKey.length);
                    dos.write(decryptedAESKey);

                    System.out.println("Decrypted key sent to client.");

                } catch (Exception e) {
                    e.printStackTrace();
                } finally {
                    try {
                        clientSocket.close();
                        System.out.println("Connection closed.\n");
                    } catch (IOException e) {
                        System.out.println("Error closing connection.");
                    }
                }
            }

        } catch (IOException e) {
            System.out.println("Server failed to start.");
        }
    }
}
