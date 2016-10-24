package isp.integrity;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class AgentCommunicationMITM {
    public static char[] concat(char[] first, char[] second) {
        char[] result = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        // secred shared between client1 and the service
        final String secret = "secret";

        final BlockingQueue<byte[]> alice2mitm = new LinkedBlockingQueue<>();
        final BlockingQueue<byte[]> mitm2service = new LinkedBlockingQueue<>();

        final Agent client = new Agent("CLIENT 1", alice2mitm, null, null, "SHA1") {
            @Override
            public void execute() throws Exception {
                final String message = "count=10&lat=37.351&user_id=1&long=-119.827&waffle=eggo";
                final byte[] pt = message.getBytes("UTF-8");

                final MessageDigest sha1 = MessageDigest.getInstance("SHA1");
                final byte[] tag = sha1.digest((secret + message).getBytes("UTF-8"));

                print("data = %s", message);
                print("pt   = %s", hex(pt));
                print("tag  = %s", hex(tag));

                outgoing.put(pt);
                outgoing.put(tag);
            }
        };

        final Agent mitm = new Agent("MITM (Client 2)", mitm2service, alice2mitm, null, null) {
            @Override
            public void execute() throws Exception {
                final byte[] pt = incoming.take();
                final byte[] tag = incoming.take();
                print("data = %s", new String(pt, "UTF-8"));
                print("pt   = %s", hex(pt));
                print("tag  = %s", hex(tag));
                //outgoing.put(pt);
                //outgoing.put(tag);


                // TODO: manipulate the parameters and send another valid request
                // You can assume that when the parameters repeat, the service uses the right-most value
                // For instance, to change the name of the waffle, you could send the following request
                //     count=10&lat=37.351&user_id=1&long=-119.827&waffle=eggo&waffle=liege
                final String original = "count=10&lat=37.351&user_id=1&long=-119.827&waffle=eggo";
                final char[] prefix = original.toCharArray();
                final char[] padding = new char[]{
                        80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 2, 28
                };
                final char[] suffix = "&waffle=liege".toCharArray();

                final char[] p1 = concat(prefix, padding);
                final char[] newMessageChar = concat(p1, suffix);

                print("newPT = %s", Arrays.toString(newMessageChar));

                final byte[] newPt = new String(newMessageChar).getBytes("UTF-8");
                final MessageDigest sha1 = MessageDigest.getInstance("SHA1");
                final byte[] newTag = sha1.digest(newPt);

                // print("data = %s", message);
                print("newPt   = %s", hex(newPt));
                print("newTag  = %s", hex(newTag));

                outgoing.put(newPt);
                outgoing.put(newTag);

                // print(" IN: %s", hex(bytes));
                // print("OUT: %s", hex(bytes));
            }
        };

        final Agent service = new Agent("SERVICE", null, mitm2service, null, "SHA1") {
            @Override
            public void execute() throws Exception {
                final byte[] pt = incoming.take();
                final String message = new String(pt, "UTF-8");
                final byte[] tag = incoming.take();

                print("pt   = %s", hex(pt));
                print("tag  = %s", hex(tag));

                final MessageDigest sha1 = MessageDigest.getInstance(this.cipher);
                final byte[] tag2 = sha1.digest((secret + message).getBytes("UTF-8"));
                print("tag2 = %s", hex(tag2));

                if (Arrays.equals(tag, tag2))
                    print("Authenticity and integrity verified.");
                else
                    print("Failed to verify authenticity and integrity.");
            }
        };

        client.start();
        mitm.start();
        service.start();
    }
}
