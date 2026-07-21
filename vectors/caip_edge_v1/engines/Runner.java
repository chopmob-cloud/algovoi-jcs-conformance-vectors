// Copyright 2026 AlgoVoi (chopmob@gmail.com). Apache-2.0.
// caip_edge_v1 Java runner. Correct = Pattern.matches() (whole-input anchor). Naive =
// Pattern.find() with ^..$: Java's $ (no MULTILINE) matches before a trailing line
// terminator, so find()+^..$ SHARES the anchor trap (over-accepts trailing-newline vectors),
// exactly like Python. matches() does not, because it requires the entire input consumed.
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.regex.Pattern;

public class Runner {
    static final String CHAIN = "[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}";

    static String body(String k) {
        switch (k) {
            case "caip2":  return CHAIN;
            case "caip10": return CHAIN + ":[-.%a-zA-Z0-9]{1,128}";
            default:       return CHAIN + "/[-a-z0-9]{3,8}:[-.%a-zA-Z0-9]{1,128}(/[-.%a-zA-Z0-9]{1,78})?";
        }
    }

    public static void main(String[] a) throws Exception {
        var hf = HexFormat.of();
        int n = 0, pass = 0, trap = 0;
        for (String ln : Files.readAllLines(Path.of("corpus.tsv"), StandardCharsets.UTF_8)) {
            String[] p = ln.split("\t", 3);
            if (p.length < 3) continue;
            String exp = p[0], kind = p[1];
            String s = new String(hf.parseHex(p[2]), StandardCharsets.UTF_8);
            boolean want = exp.equals("accept");
            if (Pattern.matches(body(kind), s) == want) pass++;
            n++;
            if (exp.equals("reject") && Pattern.compile("^" + body(kind) + "$").matcher(s).find()) trap++;
        }
        System.out.printf("Java     correct %d/%d | naive find()+^..$ over-accepts %d reject-vectors%n", pass, n, trap);
        System.exit(pass == n ? 0 : 1);
    }
}
