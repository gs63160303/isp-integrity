package isp.integrity;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.KeyGenerator;
import java.nio.charset.StandardCharsets;
import java.security.Key;

public class AgentCommunicationGCM {
    public static void main(String[] args) throws Exception {
        /*
         * Alice and Bob share a secret session key that will be
         * used for AES in GCM.
         */
        final Key key = KeyGenerator.getInstance("AES").generateKey();

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                /*
                 * Alice:
                 * - creates an AES/GCM cipher,
                 * - initializes it for encryption and with given key.
                 * - encrypts the messages,
                 * - sends the ciphertext and the IV to Bob.
                 */
                final String text = "I hope you get this message intact and in secret. Kisses, Alice.";
                final byte[] pt = text.getBytes(StandardCharsets.UTF_8);
                send("bob", pt);


            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                /*
                 * Bob:
                 * - receives the ciphertext and the IV
                 * - creates a AES/GCM cipher
                 * - initializes the cipher with decryption mode, the key and the IV
                 * - decrypts the message and prints it.
                 */

            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
