import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/** Old hand tokenizer vs the regex replacement, over every main source and a few edge inputs. */
public class Compare {

    static final Pattern COMMENT_OR_LITERAL =
            Pattern.compile("//[^\n]*|/\\*.*?\\*/|\"(?:[^\"\\\\]|\\\\.)*+\"|'(?:[^'\\\\]|\\\\.)*+'", Pattern.DOTALL);

    static String regex(String source) {
        Matcher matcher = COMMENT_OR_LITERAL.matcher(source);
        StringBuffer code = new StringBuffer();
        while (matcher.find()) {
            String token = matcher.group();
            matcher.appendReplacement(code, token.startsWith("/") ? "" : Matcher.quoteReplacement(token));
        }
        return matcher.appendTail(code).toString();
    }

    static String old(String source) {
        StringBuilder out = new StringBuilder(source.length());
        boolean inBlockComment = false;
        boolean inString = false;
        boolean inChar = false;
        for (int i = 0; i < source.length(); i++) {
            char c = source.charAt(i);
            char next = i + 1 < source.length() ? source.charAt(i + 1) : '\0';
            if (inBlockComment) {
                if (c == '*' && next == '/') {
                    inBlockComment = false;
                    i++;
                }
                continue;
            }
            if (inString || inChar) {
                if (c == '\\') {
                    out.append(c).append(next);
                    i++;
                    continue;
                }
                if (inString && c == '"') {
                    inString = false;
                }
                if (inChar && c == '\'') {
                    inChar = false;
                }
                out.append(c);
                continue;
            }
            if (c == '/' && next == '/') {
                while (i < source.length() && source.charAt(i) != '\n') {
                    i++;
                }
                out.append('\n');
                continue;
            }
            if (c == '/' && next == '*') {
                inBlockComment = true;
                i++;
                continue;
            }
            if (c == '"') {
                inString = true;
            }
            if (c == '\'') {
                inChar = true;
            }
            out.append(c);
        }
        return out.toString();
    }

    public static void main(String[] args) throws Exception {
        int files = 0;
        int differ = 0;
        for (String root : args) {
            List<Path> paths;
            try (Stream<Path> walk = Files.walk(Paths.get(root))) {
                paths = walk.filter(p -> p.toString().endsWith(".java")).collect(Collectors.toList());
            }
            for (Path p : paths) {
                String s = new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
                files++;
                if (!old(s).equals(regex(s))) {
                    differ++;
                    System.out.println("DIFFER " + p);
                }
            }
        }
        System.out.println(files + " files, " + differ + " differ");
        String[] edges = {
            "a = \"http://x\"; // https://y\nb",
            "c = '\"'; d = \"/* not */\"; /* gone \" */ e",
            "f = '\\''; g = \"\\\" // still string\"; h // gone\ni",
            "j = '/'; k = a / b / c; l /* a */ m",
            "n = \"\\\\\"; // gone\no",
        };
        for (String e : edges) {
            System.out.println((old(e).equals(regex(e)) ? "same   " : "DIFFER ") + regex(e).replace("\n", "\\n"));
        }
        StringBuilder big = new StringBuilder("x = \"");
        for (int i = 0; i < 200_000; i++) {
            big.append(i % 7 == 0 ? "\\n" : "a");
        }
        big.append("\"; /* ").append(new String(new char[200_000]).replace('\0', 'z')).append(" */ y");
        System.out.println("big literal + comment: " + old(big.toString()).equals(regex(big.toString())));
    }
}
