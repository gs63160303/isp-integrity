package isp.integrity;
/*
 * Implement simple MAC-ing scheme using Hmac with SHA-1
 *
 * http://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#Mac
 */

import javax.crypto.KeyGenerator;
import java.security.Key;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class AgentCommunicationHMAC {
    public static void main(String[] args) throws Exception {

        /**
         * STEP 1.
         * Alice and Bob agree upon a shared secret session key that will be 
         * used for hash based message authentication code.
         */
        final Key hmacKey = KeyGenerator.getInstance("HmacSHA256").generateKey();

        /**
         * STEP 2.
         * Setup an insecure communication channel.
         */
        final BlockingQueue<byte[]> alice2bob = new LinkedBlockingQueue<>();
        final BlockingQueue<byte[]> bob2alice = new LinkedBlockingQueue<>();

        /**
         * STEP 3. Alice
         * - uses shared secret session key to create HMAC.
         * - sends a message that is comprised of:
         *   o message
         *   o HMAC.
         */
        final Agent alice = new Agent("alice", bob2alice, alice2bob, hmacKey, "HmacSHA256") {
            @Override
            public void execute() throws Exception {
                /*
                 * STEP 3.1
                 * Alice writes a message and sends to Bob.
                 */
                final String text = "I love you Bob. Kisses, Alice.";
                final byte[] pt = text.getBytes("UTF-8");
                outgoing.put(pt);

                /*
                 * TODO: STEP 3.2
                 * In addition, Alice creates HMAC using selected
                 * hash algorithm and shared secret session key.
                 */
            }
        };

        /*
         * STEP 4. Bob:
         * - receives the message that is comprised of:
         *   o message
         *   o HMAC
         * - uses shared secret session key to
         *   verify message authenticity and integrity.
         */
        final Agent bob = new Agent("bob", alice2bob, bob2alice, hmacKey, "HmacSHA256") {

            @Override
            public void execute() throws Exception {
                /*
                 * TODO STEP 4.1
                 * Bob receives the message from Alice.
                 */


                /*
                 * TODO: STEP 4.2
                 * Bob calculates new HMAC using selected hash algorithm,
                 * shared secret session key and received text.
                 */


                /*
                 * TODO: STEP 4.3
                 * Verify if received and calculated HMAC match.
                 */
            }
        };

        bob.start();
        alice.start();
    }
}
