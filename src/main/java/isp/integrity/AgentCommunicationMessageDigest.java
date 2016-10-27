package isp.integrity;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.logging.Logger;

public class AgentCommunicationMessageDigest {

    private final static Logger LOG = Logger.getLogger(AgentCommunicationMessageDigest.class.getCanonicalName());

    public static void main(String[] args) {

        /**
         * STEP 1.
         * Setup an insecure communication channel.
         */
        final BlockingQueue<byte[]> alice2bob = new LinkedBlockingQueue<>();
        final BlockingQueue<byte[]> bob2alice = new LinkedBlockingQueue<>();

        /**
         * STEP 2.
         * Agent Alice definition:
         * - uses the communication channel,
         * - sends a message that is comprised of:
         *   o message
         *   o Message Digest
         * - checks if received and calculated message digest checksum match.
         */
        final Agent alice = new Agent("alice", bob2alice, alice2bob, null, "SHA-256") {

            @Override
            public void execute() throws Exception {
                /**
                 * STEP 2.1
                 * Alice writes a message and sends to Bob.
                 * This action is recorded in Alice's log.
                 */
                final String message = "I love you Bob. Kisses, Alice.";
                outgoing.put(message.getBytes("UTF-8"));

                /**
                 * TODO: STEP 2.2
                 * In addition, Alice creates message digest using selected
                 * hash algorithm.
                 */
            }
        };

        /**
         * STEP 3. Agent Bob
         * - uses the communication channel,
         * - receives the message that is comprised of:
         *   - message
         *   - message digest
         * - checks if received and calculated message digest checksum match.
         */
        final Agent bob = new Agent("bob", alice2bob, bob2alice, null, "SHA-256") {
            @Override
            public void execute() throws Exception {
                /**
                 * STEP 3.1
                 * Bob receives the message from Alice.
                 * This action is recorded in Bob's log.
                 */
                final byte[] pt = incoming.take();
                print("received: %s", new String(pt, "UTF-8"));

                /**
                 * TODO: STEP 3.2
                 * Bob calculates new message digest using selected hash algorithm and
                 * received text.
                 */

                // TODO STEP 3.3 Verify if received and calculated message digest checksum match.
            }
        };

        bob.start();
        alice.start();
    }
}
