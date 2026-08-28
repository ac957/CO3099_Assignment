/* This program generates a pair of matching public/private RSA keys.
 * It takes a userid as an argument, and places the generated keys in
 * "<userid>.pub" and "<userid>.prv" in the current working directory.*/

import java.io.*;
import java.security.*;

public class RSAKeyGenerator {

    public static void main(String [] args) throws Exception {

        if (args.length != 1) {
            System.err.println("Usage: java RSAKeyGen userid");
            System.exit(-1);
        }

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.genKeyPair();

        FileOutputStream fos = new FileOutputStream(args[0] + ".pub");
        fos.write(kp.getPublic().getEncoded());
        fos.close();

        fos = new FileOutputStream(args[0] + ".prv");
        fos.write(kp.getPrivate().getEncoded());
        fos.close();

    }

}
