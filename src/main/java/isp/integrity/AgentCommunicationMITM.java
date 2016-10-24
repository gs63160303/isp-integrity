package isp.integrity;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class AgentCommunicationMITM {
    public static byte[] concat(byte[] first, byte[] second) {
        byte[] result = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        // secret shared between client1 and the service
        final String secret = "secretsecret22";

        final BlockingQueue<byte[]> alice2mitm = new LinkedBlockingQueue<>();
        final BlockingQueue<byte[]> mitm2service = new LinkedBlockingQueue<>();

        final Agent client = new Agent("CLIENT 1", alice2mitm, null, null, "SHA1") {
            @Override
            public void execute() throws Exception {
                final String message = "count=10&lat=37.351&user_id=1&long=-119.827&waffle=eggo";
                final byte[] pt = message.getBytes("UTF-8");

                final MessageDigest d = MessageDigest.getInstance(cipher);
                d.update(secret.getBytes("UTF-8"));
                final byte[] tag = d.digest(pt);

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
                final String message = new String(pt, "UTF-8");
                print("data    = %s", message);
                print("pt      = %s", hex(pt));
                print("tag     = %s", hex(tag));
                //outgoing.put(pt);
                //outgoing.put(tag);

                // TODO: manipulate the parameters and send another valid request
                // You can assume that when the parameters repeat, the service uses the right-most value
                // For instance, to change the name of the waffle, you could send the following request
                //     count=10&lat=37.351&user_id=1&long=-119.827&waffle=eggo&waffle=liege
                final byte[] padding = new byte[]{
                        (byte) 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0x02, 0x28
                };
                System.out.println(Arrays.toString(padding));
                final byte[] suffix = "&waffle=liege".getBytes("UTF-8");

                final byte[] p1 = concat(pt, padding);
                final byte[] newMessageChar = concat(p1, suffix);

                final byte[] newPt = new String(newMessageChar).getBytes("UTF-8");
                final MessageDigest d = MessageDigest.getInstance("SHA1");
                d.update(tag);
                d.update("&waffle=liege".getBytes("UTF-8"));
                final byte[] newTag = d.digest();

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
                final byte[] tagReceived = incoming.take();

                print("pt     = %s", hex(pt));
                print("tag_r  = %s", hex(tagReceived));

                final MessageDigest d = MessageDigest.getInstance(cipher);
                final byte[] tagComputed = d.digest((secret + message).getBytes("UTF-8"));
                print("tag_c  = %s", hex(tagComputed));

                if (Arrays.equals(tagReceived, tagComputed))
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
