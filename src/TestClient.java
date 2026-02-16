import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;

public class TestClient {

    public static void main(String[] args) throws Exception {

        String userid = "alice";

        // 1️⃣ Load user's private key (alice.prv)
        byte[] prvKeyBytes =
                Files.readAllBytes(Path.of(userid + ".prv"));

        PKCS8EncodedKeySpec prvSpec =
                new PKCS8EncodedKeySpec(prvKeyBytes);

        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey userPrivateKey =
                kf.generatePrivate(prvSpec);

        // 2️⃣ Dummy encrypted AES key (just for testing)
        byte[] encryptedAESKey =
                Files.readAllBytes(Path.of("aes.key"));


        // 3️⃣ Create signature
        Signature sig =
                Signature.getInstance("SHA256withRSA");

        sig.initSign(userPrivateKey);
        sig.update(userid.getBytes("UTF8"));
        sig.update(encryptedAESKey);

        byte[] signatureBytes = sig.sign();

        // 4️⃣ Connect to server
        Socket socket = new Socket("localhost", 1234);

        DataOutputStream dos =
                new DataOutputStream(socket.getOutputStream());

        DataInputStream dis =
                new DataInputStream(socket.getInputStream());

        // 5️⃣ Send userid
        dos.writeUTF(userid);

        // 6️⃣ Send encrypted AES key
        dos.writeInt(encryptedAESKey.length);
        dos.write(encryptedAESKey);

        // 7️⃣ Send signature
        dos.writeInt(signatureBytes.length);
        dos.write(signatureBytes);

        // 8️⃣ Receive decrypted AES key
        int responseLength = dis.readInt();

        if (responseLength == 0) {
            System.out.println("Server rejected signature.");
        } else {
            byte[] decryptedKey =
                    new byte[responseLength];
            dis.readFully(decryptedKey);

            System.out.println("Received decrypted key from server.");
        }

        socket.close();
    }
}
