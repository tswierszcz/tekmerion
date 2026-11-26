import fx.research.Extractor;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

/**
 * Checked-in RH-T4 harness for the Ariadne control library. It calls only the
 * public API fx.research.Extractor#extract(InputStream, Path) once.
 * Arguments: confinement directory, entry name, entry body.
 * The last stdout line is a tekmerion-harness-result-1 report; the security
 * assertion is evaluated by the host, not here.
 */
public class ExtractHarness {
    public static void main(String[] args) {
        String exception = "";
        try {
            Path dir = Path.of(args[0]);
            byte[] name = args[1].getBytes(StandardCharsets.UTF_8);
            byte[] body = args[2].getBytes(StandardCharsets.UTF_8);
            if (name.length > 255) throw new IllegalArgumentException("entry name longer than one length byte");
            ByteArrayOutputStream in = new ByteArrayOutputStream();
            in.write(name.length);
            in.write(name);
            in.write(body);
            new Extractor().extract(new ByteArrayInputStream(in.toByteArray()), dir);
        } catch (Throwable t) {
            exception = t.getClass().getName() + ": " + t.getMessage();
        }
        System.out.println("{\"schema_version\":\"tekmerion-harness-result-1\",\"invoked\":\"fx.research.Extractor#extract(Ljava/io/InputStream;Ljava/nio/file/Path;)V\",\"exception\":" + quote(exception) + "}");
    }

    static String quote(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            if (c == '"' || c == '\\') b.append('\\').append(c);
            else if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
            else b.append(c);
        }
        return b.append('"').toString();
    }
}
