import java.util.Arrays;
public final class Probe2 {
    static String repeat(char c, int n) { char[] cs = new char[n]; Arrays.fill(cs, c); return new String(cs); }
    public static void main(String[] a) {
        int limit = 3145728;
        String ascii = repeat('x', limit);          // runs the whole loop, all ASCII
        String asciiOver = repeat('x', limit - 5) + "ééé"; // mixed
        String e = repeat('é', limit / 2 + 1);
        int warm = Integer.parseInt(a[0]);
        for (int k = 0; k < warm; k++) Probe.exceeds(ascii, limit);
        boolean r = Probe.exceeds(e, limit);
        System.out.println("warm " + warm + " -> exceeds(e) = " + r + (r ? "" : "  WRONG"));
    }
}
