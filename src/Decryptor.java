import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Decryptor {

    public static void main(String[] args) {

        if (args.length != 3) {
            System.out.println("Usage: java Decryptor <host> <port> <userid>");
            return;
        }

        String host = args[0];
        int port = Integer.parseInt(args[1]);
        String userid = args[2];

        try {

            System.out.println("Dear customer, thank you for purchasing this software.");
            System.out.println("We are here to help you recover your files from this horrible attack.");
            System.out.println("Trying to decrypt files...");

            // 1️⃣ Read encrypted AES key (aes.key)
            byte[] encryptedAESKey = Files.readAllBytes(Path.of("aes.key"));

            // 2️⃣ Load user's private key (userid.prv)
            byte[] prvBytes = Files.readAllBytes(Path.of(userid + ".prv"));
            PKCS8EncodedKeySpec prvSpec = new PKCS8EncodedKeySpec(prvBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey userPrivateKey = kf.generatePrivate(prvSpec);

            // 3️⃣ Generate signature over (userid + encryptedAESKey)
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initSign(userPrivateKey);
            sig.update(userid.getBytes("UTF8"));
            sig.update(encryptedAESKey);
            byte[] signatureBytes = sig.sign();

            // 4️⃣ Connect to server
            Socket socket = new Socket(host, port);
            DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
            DataInputStream dis = new DataInputStream(socket.getInputStream());

            // 5️⃣ Send data in agreed order
            dos.writeUTF(userid);

            dos.writeInt(encryptedAESKey.length);
            dos.write(encryptedAESKey);

            dos.writeInt(signatureBytes.length);
            dos.write(signatureBytes);

            // 6️⃣ Receive decrypted AES key
            int length = dis.readInt();

            if (length == 0) {
                System.out.println("Unfortunately we cannot verify your identity.");
                socket.close();
                return;
            }

            byte[] decryptedAESKey = new byte[length];
            dis.readFully(decryptedAESKey);

            socket.close();

            // 7️⃣ Reconstruct AES key
            SecretKeySpec aesKey = new SecretKeySpec(decryptedAESKey, "AES");

            // 8️⃣ Prepare IV (16 zero bytes)
            byte[] ivBytes = new byte[16];
            IvParameterSpec iv = new IvParameterSpec(ivBytes);

            // 9️⃣ Read encrypted file
            byte[] encryptedFile = Files.readAllBytes(Path.of("test.txt.cry"));

            // 🔟 Decrypt file using AES/CBC/PKCS5Padding
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, aesKey, iv);

            byte[] decryptedFile = cipher.doFinal(encryptedFile);

            // 11️⃣ Write decrypted file back
            Files.write(Path.of("test.txt"), decryptedFile);

            System.out.println("Success! Your files have now been recovered!");

        } catch (Exception e) {
            System.out.println("Error during decryption.");
        }
    }
}

