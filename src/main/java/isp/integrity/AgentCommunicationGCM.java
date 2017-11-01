package isp.integrity;

import javax.crypto.KeyGenerator;
import java.security.Key;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class AgentCommunicationGCM {
    public static void main(String[] args) throws Exception {

        /**
         * STEP 1.
         * Alice and Bob agree upon a shared secret session key.
         */
        final Key sharedKey = KeyGenerator.getInstance("AES").generateKey();

        /**
         * STEP 2.
         * Setup an insecure communication channel.
         */
        final BlockingQueue<byte[]> alice2bob = new LinkedBlockingQueue<>();
        final BlockingQueue<byte[]> bob2alice = new LinkedBlockingQueue<>();

        /**
         * STEP 3.
         * Agent Alice:
         * - creates a AES/GCM cipher,
         * - initializes it for encryption and with given key.
         * - encrypts the messages,
         * - sends the ciphertext and the IV to Bob.
         */
        final Agent alice = new Agent("alice", bob2alice, alice2bob, sharedKey, "AES/GCM/NoPadding") {
            @Override
            public void execute() throws Exception {
                final String text = "I love you Bob. Kisses, Alice.";
                final byte[] pt = text.getBytes("UTF-8");


            }
        };

        /**
         * STEP 4.
         * Agent Bob:
         * - receives the ciphertext and the IV
         * - creates a AES/GCM cipher
         * - initializes the cipher with decryption mode, the key and the IV
         * - decrypts the message and prints it.
         */
        final Agent bob = new Agent("bob", alice2bob, bob2alice, sharedKey, "AES/GCM/NoPadding") {

            @Override
            public void execute() throws Exception {

            }
        };

        bob.start();
        alice.start();
    }
}
