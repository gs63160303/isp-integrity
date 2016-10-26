package isp.integrity;

import javax.xml.bind.DatatypeConverter;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

public class T1 {

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

    public static  int fromArray(byte[] payload){
        ByteBuffer buffer = ByteBuffer.wrap(payload);
        buffer.order(ByteOrder.BIG_ENDIAN);
        return buffer.getInt();
    }

    public static byte[] toArray(long value){
        ByteBuffer buffer = ByteBuffer.allocate(8);
        buffer.order(ByteOrder.BIG_ENDIAN);
        buffer.putLong(value);
        buffer.flip();
        return buffer.array();
    }

    public static void main(String[] args) throws Exception {
        int a = 1024 * 1024;
        final byte[] bytes = toArray(a);
        System.out.println(Arrays.toString(bytes));

        byte b = (byte) (a >>> 24);
        byte c = (byte) (a >>> 16);
        byte d = (byte) (a >>> 8);
        byte e = (byte) a;

        print("%d %d %d %d", b, c, d, e);
    }
}