package isp.integrity;

import sun.security.provider.SHA;

import javax.xml.bind.DatatypeConverter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.DigestException;

public class HLE {

    /*private static class MySHA {
        final SHA alg = new SHA();
        final int[] state = new int[5];
        long bytesProcessed = 0;

        void engineUpdate(byte[] var1, int var2, int var3) {
            try {
                final Method engineUpdate = alg.getClass().getSuperclass().getDeclaredMethod(
                        "engineUpdate", byte.class, int.class, int.class);
                engineUpdate.setAccessible(true);
                engineUpdate.invoke(alg, var1, var2, var3);
            } catch (NoSuchMethodException | InvocationTargetException | IllegalAccessException e) {
                e.printStackTrace();
            }
        }

    }


    private static final String KEY = "NoNeedToRecoverKey";

    private static final String TOMAC = "SecuredResource";

    private static final String EXTENSION = "TheResourceRemainsUnsecured";

    private static final SHA SHA1 = new SHA();

    private static final int BLOCKSIZE = 64;

    private static final byte[] PADDING = new byte[136];

    static {
        PADDING[0] = (byte) 0x80;
    }

    public static void main(String[] args) throws Exception {
        byte[] extensionBytes = EXTENSION.getBytes("UTF8");
        byte[] toMACBytes = TOMAC.getBytes("UTF8");
        byte[] originalMAC = createMAC(toMACBytes);
        System.out.println("Original MAC  : " + hex(originalMAC));

        byte[] macCandidate;
        byte[] hashInput;
        int pointer = 0;

        System.out.println("Recover digest state...");
        SHA1.engineReset();
        // set internal state to the one of the original MAC
        SHA1.state[0] = bytesToInt(originalMAC[0], originalMAC[1],
                originalMAC[2], originalMAC[3]);
        SHA1.state[1] = bytesToInt(originalMAC[4], originalMAC[5],
                originalMAC[6], originalMAC[7]);
        SHA1.state[2] = bytesToInt(originalMAC[8], originalMAC[9],
                originalMAC[10], originalMAC[11]);
        SHA1.state[3] = bytesToInt(originalMAC[12], originalMAC[13],
                originalMAC[14], originalMAC[15]);
        SHA1.state[4] = bytesToInt(originalMAC[16], originalMAC[17],
                originalMAC[18], originalMAC[19]);
        SHA1.bytesProcessed = BLOCKSIZE;

        System.out.println("Compute extension MAC...");
        SHA1.engineUpdate(extensionBytes, 0, extensionBytes.length);
        // compute the extended hash
        macCandidate = SHA1.engineDigest();
        System.out.println("Extended MAC  : "
                + hex(macCandidate));

        System.out.println("Trying to find suitable input....");
        // determine the necessary input....
        int j = 0;
        for (int i = 1; i <= PADDING.length; i++) {
            hashInput = new byte[toMACBytes.length + i
                    + 8 + extensionBytes.length];
            pointer = 0;


            // # add original message
            System.arraycopy(toMACBytes, 0, hashInput, pointer,
                    toMACBytes.length);
            pointer += toMACBytes.length;
            // # add padding
            System.arraycopy(PADDING, 0, hashInput, pointer, i);
            pointer += i;
            // # add length of user data (8 bytes)
            // j is the computed length of the original message in bits
            // (blockSize - padding length - 8 length bytes)
            j = (BLOCKSIZE - i - 8) << 3;
            // the first word is 0 in our case, due to only 32 bit int
            hashInput[pointer] = 0;
            hashInput[pointer + 1] = 0;
            hashInput[pointer + 2] = 0;
            hashInput[pointer + 3] = 0;
            hashInput[pointer + 4] = (byte) ((j >>> 24));
            hashInput[pointer + 5] = (byte) ((j >>> 16));
            hashInput[pointer + 6] = (byte) ((j >>> 8));
            hashInput[pointer + 7] = (byte) (j);
            pointer += 8;
            // # add extension
            System.arraycopy(extensionBytes, 0, hashInput, pointer,
                    extensionBytes.length);
            pointer += extensionBytes.length;

            // # check guess
            if (isMACCorrect(macCandidate, hashInput)) {
                System.out.println("==> Hash input    : "
                        + hex(hashInput));
                System.out.println("==> Padding Length: "
                        + i);
                System.out.println("==> Secret Length : "
                        + (BLOCKSIZE - toMACBytes.length - i - 8));
                break;
            }
        }
    }

    private static int bytesToInt(byte... bytes) {
        return ((0xFF & bytes[0]) << 24
                | (0xFF & bytes[1]) << 16
                | (0xFF & bytes[2]) << 8
                | (0xFF & bytes[3]));
    }

    private static final boolean isMACCorrect(final byte[] macToCheck,
                                              final byte[] msg) throws DigestException {
        boolean result = true;
        byte[] referenceHash = createMAC(msg);
        System.out.println("Reference hash: "
                + hex(referenceHash));

        if (referenceHash.length != macToCheck.length) {
            result = false;
        } else {
            for (int i = 0; i < referenceHash.length; i++) {
                if (referenceHash[i] != macToCheck[i]) {
                    result = false;
                    break;
                }
            }
        }

        return result;
    }

    private static String hex(byte[] bytes) {
        return DatatypeConverter.printHexBinary(bytes);
    }

    private static final byte[] createMAC(final byte[] msg) throws
            DigestException {
        byte[] utf8KeyBytes = KEY.getBytes("UTF8");

        SHA1.engineReset();
        SHA1.engineUpdate(utf8KeyBytes, 0, utf8KeyBytes.length);
        SHA1.engineUpdate(msg, 0, msg.length);
        return SHA1.engineDigest();
    }*/
}
