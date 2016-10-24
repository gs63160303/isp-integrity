package isp.integrity;

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
        final Agent alice = new Agent("alice", bob2alice, alice2bob, null, "MD5") {

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

                /**
                 * TODO STEP 2.3
                 * Special care has to be taken when transferring binary stream
                 * over the communication channel: convert byte array into string
                 * of HEX values with DatatypeConverter.printHexBinary(byte[])
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
        final Agent bob = new Agent("bob", alice2bob, bob2alice, null, "MD5") {

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
                 * TODO STEP 3.2
                 * Special care has to be taken when transferring binary stream
                 * over the communication channel: convert received string into
                 * byte array with DatatypeConverter.parseHexBinary(String)
                 */

                /**
                 * TODO: STEP 3.3
                 * Bob calculates new message digest using selected hash algorithm and
                 * received text.
                 */

                /**
                 * TODO STEP 3.4
                 * Verify if received and calculated message digest checksum match.
                 */
                    /*if (Arrays.equals(receivedDigest, digestRecomputed)) {
                        LOG.info("Integrity checked");
                    } else {
                        LOG.warning("Integrity check failed.");
                    }*/
            }
        };

        /**
         * STEP 4.
         * Two commands below "fire" both agents and the fun begins ... :-)
         */
        bob.start();
        alice.start();
    }
}
