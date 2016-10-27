package isp.integrity;

import javax.xml.bind.DatatypeConverter;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.util.Arrays;

public class LEA {

    public static void main(String[] args) throws Exception {
        // Initial data
        final byte[] secret = "password".getBytes("UTF-8");
        final byte[] message = "my message".getBytes("UTF8");
        final MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        sha1.update(secret);
        sha1.update(message);
        final byte[] mac = sha1.digest();
        System.out.printf("Original MAC: %s%n", hex(mac));

        // Data to be added
        final int messageSize = message.length + secret.length;

        // 8 bytes for length + 1 block for 0x80
        final int numBlocks = (int) Math.ceil((messageSize + 9.0) / 64.0);
        final byte[] addition = "Additionally added data".getBytes("UTF8");

        final ModifiedSHA1 mySHA = new ModifiedSHA1();
        mySHA.setState(mac, numBlocks);
        mySHA.update(addition);
        final byte[] newMac = mySHA.digest();
        System.out.printf("New MAC: %s%n", hex(newMac));

        // new message (original + addition - secret)
        final byte[] newMessage = new byte[ModifiedSHA1.BLOCK_SIZE * numBlocks + addition.length - secret.length];
        int offset = 0;

        // original message
        System.arraycopy(message, 0, newMessage, offset, message.length);
        offset += message.length;

        // original padding (without length)
        final int oldPaddingLength = ModifiedSHA1.BLOCK_SIZE * numBlocks - message.length - secret.length - 8;
        System.arraycopy(ModifiedSHA1.PADDING, 0, newMessage, offset, oldPaddingLength);
        offset += oldPaddingLength;

        // padding [original message length in bits] (8 bytes in big endian)
        final ByteBuffer buffer = ByteBuffer.allocate(8);
        buffer.order(ByteOrder.BIG_ENDIAN);
        buffer.putLong(messageSize * 8); // longs in Java have 8 bytes
        final byte[] messageSizeBytes = buffer.array();

        System.arraycopy(messageSizeBytes, 0, newMessage, offset, messageSizeBytes.length);
        offset += messageSizeBytes.length;

        // add extension
        System.arraycopy(addition, 0, newMessage, offset, addition.length);

        if (checkMAC(newMac, newMessage, secret)) {
            System.out.printf("==> Original PT     : %s%n", hex(message));
            System.out.printf("==> Secret          : %s%n", hex(secret));
            System.out.printf("==> Modified PT     : %s%n", hex(newMessage));
            System.out.printf("==> Actual string   : %s%n", new String(newMessage, "UTF-8"));
        } else {
            System.err.println("MAC INVALID");
        }
    }

    private static boolean checkMAC(byte[] mac, byte[] message, byte[] secret) throws Exception {
        final MessageDigest md = MessageDigest.getInstance("SHA-1");
        md.update(secret);
        final byte[] withSecret = md.digest(message);
        return Arrays.equals(mac, withSecret);
    }

    private static String hex(byte[] bytes) {
        return DatatypeConverter.printHexBinary(bytes);
    }
}
