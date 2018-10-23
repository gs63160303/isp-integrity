package isp.integrity;

import fri.isp.Agent;
import fri.isp.Environment;

import java.nio.charset.StandardCharsets;

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
                final String message = "I hope you get this message intact. Kisses, Alice.";
                send("bob", message.getBytes(StandardCharsets.UTF_8));

                // TODO: Alice creates message digest using SHA-256.
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

            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
