package aprvj.gen;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Provider;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Writes config/minimal/reachability-metadata.json deterministically from
 * BouncyCastle itself, so nothing in it is a trace of one test run:
 *
 * <ol>
 *   <li>every {@code $Mappings} class the BouncyCastleProvider constructor
 *       loads by name (its private static name tables), because the
 *       constructor loads them all and a missing one is silently skipped,
 *       taking its algorithms with it;</li>
 *   <li>every provider service class of the JCA types the verifier reaches
 *       (Signature, MessageDigest, KeyFactory, AlgorithmParameters,
 *       CertificateFactory, CertPathBuilder, CertPathValidator, CertStore),
 *       with its public constructors, because the verifier accepts whatever
 *       signature algorithm a pinned chain uses;</li>
 *   <li>the fixed non-BouncyCastle entries in {@code base.json} (payload
 *       models for Jackson, the Apple root resources, time-zone data).</li>
 * </ol>
 *
 * Ciphers, MACs, KEMs, key agreement, key stores, DRBGs and KDFs are not
 * registered: the verifier never asks for them.
 *
 *   java -cp bcprov.jar:jackson*.jar:gen aprvj.gen.MetadataGen base.json out.json
 */
public final class MetadataGen {

    static final Set<String> TYPES = new TreeSet<String>(Arrays.asList(
            "Signature", "MessageDigest", "KeyFactory", "AlgorithmParameters",
            "CertificateFactory", "CertPathBuilder", "CertPathValidator", "CertStore"));

    public static void main(String[] args) throws Exception {
        ObjectMapper json = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
        @SuppressWarnings("unchecked")
        Map<String, Object> base = json.readValue(Files.readAllBytes(Paths.get(args[0])), Map.class);

        Map<String, Map<String, Object>> reflection = new TreeMap<String, Map<String, Object>>();
        // 1. $Mappings, from the provider's own tables.
        Object[][] tables = {
            {"SYMMETRIC_GENERIC", "org.bouncycastle.jcajce.provider.symmetric."},
            {"SYMMETRIC_MACS", "org.bouncycastle.jcajce.provider.symmetric."},
            {"SYMMETRIC_CIPHERS", "org.bouncycastle.jcajce.provider.symmetric."},
            {"ASYMMETRIC_GENERIC", "org.bouncycastle.jcajce.provider.asymmetric."},
            {"ASYMMETRIC_CIPHERS", "org.bouncycastle.jcajce.provider.asymmetric."},
            {"DIGESTS", "org.bouncycastle.jcajce.provider.digest."},
            {"KEYSTORES", "org.bouncycastle.jcajce.provider.keystore."},
            {"SECURE_RANDOMS", "org.bouncycastle.jcajce.provider.drbg."},
            {"KDFS", "org.bouncycastle.jcajce.provider.kdf."},
        };
        int mappings = 0;
        for (Object[] table : tables) {
            Field field = BouncyCastleProvider.class.getDeclaredField((String) table[0]);
            field.setAccessible(true);
            Object[] names = (Object[]) field.get(null);
            for (Object entry : names) {
                String name = entry instanceof String ? (String) entry : serviceName(entry);
                String className = table[1] + name + "$Mappings";
                try {
                    Class.forName(className, false, MetadataGen.class.getClassLoader());
                } catch (ClassNotFoundException absent) {
                    continue; // the provider skips it on the JVM too
                }
                reflection.put(className, constructors(className, true));
                mappings++;
            }
        }
        // 2. Service classes of the verification types.
        Provider provider = new BouncyCastleProvider();
        int services = 0;
        for (Provider.Service service : provider.getServices()) {
            if (!TYPES.contains(service.getType()) || reflection.containsKey(service.getClassName())) {
                continue;
            }
            reflection.put(service.getClassName(), constructors(service.getClassName(), false));
            services++;
        }
        // The PKIX spis load a revocation checker class by name.
        reflection.put("java.security.cert.PKIXRevocationChecker", entry("java.security.cert.PKIXRevocationChecker"));

        List<Object> out = new ArrayList<Object>();
        @SuppressWarnings("unchecked")
        List<Object> fixed = (List<Object>) base.get("reflection");
        out.addAll(fixed);
        out.addAll(reflection.values());
        Map<String, Object> doc = new LinkedHashMap<String, Object>();
        doc.put("comment", "Generated by aprvj.gen.MetadataGen from BouncyCastle " + provider.getVersionStr()
                + ": " + mappings + " $Mappings, " + services + " service classes of " + TYPES
                + ", plus base.json. Do not edit by hand.");
        doc.put("reflection", out);
        doc.put("resources", base.get("resources"));
        Files.write(Paths.get(args[1]), json.writeValueAsBytes(doc));
        System.err.println(mappings + " mappings, " + services + " services, " + out.size() + " reflection entries");
    }

    private static String serviceName(Object properties) throws Exception {
        return ((org.bouncycastle.crypto.CryptoServiceProperties) properties).getServiceName();
    }

    private static Map<String, Object> entry(String type) {
        Map<String, Object> e = new LinkedHashMap<String, Object>();
        e.put("type", type);
        return e;
    }

    /** The class with its public constructors (only the no-arg one for $Mappings). */
    private static Map<String, Object> constructors(String className, boolean noArgOnly) throws Exception {
        Class<?> type = Class.forName(className, false, MetadataGen.class.getClassLoader());
        List<Object> methods = new ArrayList<Object>();
        for (Constructor<?> c : type.getDeclaredConstructors()) {
            if (!Modifier.isPublic(c.getModifiers()) || (noArgOnly && c.getParameterCount() != 0)) {
                continue;
            }
            List<String> params = new ArrayList<String>();
            for (Class<?> p : c.getParameterTypes()) {
                params.add(p.getName());
            }
            Map<String, Object> m = new LinkedHashMap<String, Object>();
            m.put("name", "<init>");
            m.put("parameterTypes", params);
            methods.add(m);
        }
        Map<String, Object> e = entry(className);
        e.put("methods", methods);
        return e;
    }

    private MetadataGen() {}
}
