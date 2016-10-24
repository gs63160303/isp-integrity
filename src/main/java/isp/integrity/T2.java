package isp.integrity;

import sun.security.provider.SHA;

import javax.xml.bind.DatatypeConverter;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class T2 {

    public static byte[] concat(byte[] first, byte[] second) {
        byte[] result = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }

    public static void print(String s, Object... o) {
        System.out.printf(s, o);
        System.out.println();
    }

    public static String hex(byte[] in) {
        return DatatypeConverter.printHexBinary(in);
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, UnsupportedEncodingException, NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        final String secret = "secretsecret22";

        final SHA sha = new SHA();
        final Method engineUpdate = sha.getClass().getSuperclass().getDeclaredMethod("engineUpdate", byte.class);
        engineUpdate.setAccessible(true);

        for (byte b : secret.getBytes()) {
            engineUpdate.invoke(sha, b);
        }

        final Method engineDigest = sha.getClass().getSuperclass().getDeclaredMethod("engineDigest");
        engineDigest.setAccessible(true);
        final byte[] digest = (byte[]) engineDigest.invoke(sha);

        print("%s", hex(digest));

        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        print("%s", hex(sha1.digest(secret.getBytes())));

    }
}
