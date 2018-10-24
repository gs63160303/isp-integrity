package isp.integrity;

import fri.isp.Agent;
import fri.isp.Environment;

import java.nio.charset.StandardCharsets;

/**
 * An MITM example showing how merely using a collision-resistant hash
 * function is insufficient to protect against tampering
 */
public class AgentCommunicationMessageDigest {

    public static void main(String[] args) {
        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                /*
                 * Alice:
                 * - sends a message that consists of:
                 *   - a message
                 *   - and a message Digest
                 */
                final byte[] message = "I hope you get this message intact. Kisses, Alice.".getBytes(StandardCharsets.UTF_8);

                // TODO: Create the digest and send the (message, digest) pair
            }
        });

        env.add(new Agent("mallory") {
            @Override
            public void task() throws Exception {
                // Intercept the message from Alice
                final byte[] message = receive("alice");
                final byte[] tag = receive("alice");

                // TODO: Modify the message

                // Forward the modified message
                send("bob", message);
                send("bob", tag);
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                /*
                 * Bob
                 * - receives the message that is comprised of:
                 *   - message
                 *   - message digest
                 * - checks if received and calculated message digest checksum match.
                 */
                final byte[] message = receive("alice");
                final byte[] tag = receive("alice");

                // TODO: Check if the received (message, digest) pair is valid
            }
        });

        env.mitm("alice", "bob", "mallory");
        env.start();
    }
}
