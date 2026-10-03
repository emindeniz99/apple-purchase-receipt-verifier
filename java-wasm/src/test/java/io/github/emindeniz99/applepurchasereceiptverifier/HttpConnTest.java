package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.net.URI;
import org.junit.jupiter.api.Test;

/** The request head HttpConn writes, where it does not need a server to check. */
class HttpConnTest {

    /**
     * A URL source on an IPv6 literal must send a Host header the server
     * can parse: {@code Host: ::1:8080} is not one (RFC 9112 §3.2 takes the
     * URI's host, brackets included). Names and IPv4 addresses go as they are.
     */
    @Test
    void theHostHeaderBracketsAnIpv6Literal() {
        assertEquals("[::1]:8080", host("http://[::1]:8080/aprv"));
        assertEquals("[2001:db8::7]:443", host("https://[2001:db8::7]/"));
        assertEquals("127.0.0.1:8080", host("http://127.0.0.1:8080"));
        assertEquals("aprv.internal:80", host("http://aprv.internal"));
    }

    /**
     * A zone id says which interface of this host reaches a link-local
     * address; it means nothing to the server, so it does not go into the
     * Host header (RFC 6874 §4), whether the URI writes it as {@code %25}
     * or the literal carries a bare {@code %}.
     */
    @Test
    void theHostHeaderLeavesOutAnIpv6ZoneId() {
        assertEquals("[fe80::1]:8080", host("http://[fe80::1%25eth0]:8080/aprv"));
        assertEquals("[fe80::1]:8080", HttpConn.hostHeader("fe80::1%eth0", 8080));
        assertEquals("[fe80::1]:443", HttpConn.hostHeader("fe80::1%2", 443));
    }

    private static String host(String url) {
        HttpConn.Target target = ServerSources.target(URI.create(url), null);
        return HttpConn.hostHeader(target.host, target.port);
    }
}
