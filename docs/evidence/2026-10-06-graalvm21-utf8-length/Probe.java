public final class Probe {
    static boolean exceeds(String text, int limit) {
        int units = text.length();
        if (units > limit) return true;
        if (units * 3L <= limit) return false;
        long bytes = 0;
        for (int i = 0; i < units; i++) {
            char c = text.charAt(i);
            if (c < 0x80) {
                bytes += 1;
            } else if (c < 0x800) {
                bytes += 2;
            } else if (Character.isHighSurrogate(c) && i + 1 < units && Character.isLowSurrogate(text.charAt(i + 1))) {
                bytes += 4;
                i++;
            } else {
                bytes += 3;
            }
            if (bytes > limit) return true;
        }
        return false;
    }
    public static void main(String[] a) {
        int limit = 3145728;
        char[] cs = new char[limit / 2 + 1];
        java.util.Arrays.fill(cs, 'é');
        String s = new String(cs);
        int wrong = 0, n = Integer.parseInt(a[0]);
        for (int k = 0; k < n; k++) if (!exceeds(s, limit)) { wrong++; if (wrong < 5) System.out.println("wrong at " + k); }
        System.out.println("runs " + n + " wrong " + wrong);
    }
}
