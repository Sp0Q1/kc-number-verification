package com.example.keycloak.numberverification;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import org.apache.http.HttpEntity;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.Configurable;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.jboss.logging.Logger;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.connections.httpclient.SafeInputStream;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.util.JsonSerialization;

/**
 * Calls the backend verification endpoint and reduces its answer to a boolean.
 *
 * <p>The payload is assembled from configuration, so the account identifier sent alongside the
 * number can be the Keycloak user id, the username, or any custom user attribute, under whatever
 * JSON field name the backend expects.
 *
 * <p>Requests go through Keycloak's shared {@link HttpClientProvider}, so connection pooling, the
 * server-wide socket timeout (5 s by default) and the maximum response size (10 MB by default)
 * apply without any extra configuration.
 */
public class VerificationClient {

    private static final Logger LOG = Logger.getLogger(VerificationClient.class);

    /** Longest slice of a backend response that may end up in a log line or event. */
    private static final int MAX_QUOTED_BODY = 200;

    /** Upper bound on connecting when the server-wide client sets none (its default). */
    private static final int FALLBACK_CONNECT_TIMEOUT_MS = 10_000;

    private static final String[] AUTO_DETECT_FIELDS = {"verified", "valid", "result", "success"};

    private final VerificationConfig config;

    public VerificationClient(VerificationConfig config) {
        this.config = config;
    }

    /**
     * @return true if the backend accepted the number for this account
     * @throws VerificationException if the backend is unreachable or returns something unusable
     */
    public boolean verify(
            KeycloakSession session, RealmModel realm, UserModel user, String number) {
        if (!config.hasEndpoint()) {
            throw new VerificationException("No verification endpoint configured");
        }

        Map<String, String> payload = buildPayload(realm, user, number);
        LOG.debugf("Verifying number for user %s via %s", user.getId(), config.identifierSource());

        HttpRequestBase request =
                config.method() == VerificationConfig.Method.GET
                        ? buildGet(payload)
                        : buildPost(payload);

        if (config.hasApiKey()) {
            request.setHeader(config.apiKeyHeader(), config.apiKey());
        }
        request.setHeader("Accept", "application/json");

        HttpClientProvider provider = session.getProvider(HttpClientProvider.class);
        CloseableHttpClient http = provider.getHttpClient();
        request.setConfig(requestConfig(http));
        try (CloseableHttpResponse response = http.execute(request)) {
            int status = response.getStatusLine().getStatusCode();
            String body = readBody(response.getEntity(), provider.getMaxConsumedResponseSize());

            // Some APIs express "this number does not belong to this account" as 404.
            if (status == 404) {
                return false;
            }
            if (status == 401 || status == 403) {
                throw new VerificationException(
                        "Verification service rejected our credentials: " + status);
            }
            if (status < 200 || status >= 300) {
                throw new VerificationException("Verification service returned HTTP " + status);
            }
            return parse(body);
        } catch (IOException e) {
            throw new VerificationException(
                    "Verification service call failed: " + e.getMessage(), e);
        }
    }

    /**
     * Per-request settings layered on the shared client's own: redirects are never followed (the
     * API key must not travel to a Location of the backend's choosing), cookies the backend sets
     * are ignored (the client is shared by every user's login; a backend session must not leak
     * between them), and connecting is bounded even when the server-wide client leaves it
     * unbounded. Everything else, notably the socket timeout the admin configured, is kept.
     */
    private static RequestConfig requestConfig(CloseableHttpClient http) {
        RequestConfig base =
                http instanceof Configurable configurable && configurable.getConfig() != null
                        ? configurable.getConfig()
                        : RequestConfig.DEFAULT;
        RequestConfig.Builder builder =
                RequestConfig.copy(base)
                        .setRedirectsEnabled(false)
                        .setCookieSpec(CookieSpecs.IGNORE_COOKIES);
        if (base.getConnectTimeout() <= 0) {
            builder.setConnectTimeout(FALLBACK_CONNECT_TIMEOUT_MS);
        }
        return builder.build();
    }

    /** Reads at most {@code maxBytes}; a larger body is an error, not a truncated parse. */
    private static String readBody(HttpEntity entity, long maxBytes) throws IOException {
        if (entity == null) {
            return "";
        }
        Charset charset = ContentType.getOrDefault(entity).getCharset();
        try (InputStream in = new SafeInputStream(entity.getContent(), maxBytes)) {
            return new String(
                    in.readAllBytes(), charset == null ? StandardCharsets.UTF_8 : charset);
        }
    }

    /** Assembles the number, the account identifier and any extra configured fields. */
    Map<String, String> buildPayload(RealmModel realm, UserModel user, String number) {
        Map<String, String> payload = new LinkedHashMap<>();
        payload.put(config.numberField(), number);

        String identifier = resolve(user, realm, config.identifierSource());
        if (identifier == null || identifier.isBlank()) {
            throw new VerificationException(
                    "Account identifier '"
                            + config.identifierSource()
                            + "' is empty for user "
                            + user.getId()
                            + "; the backend cannot tell which account this number is for");
        }
        payload.put(config.identifierField(), identifier);

        for (Map.Entry<String, String> field : config.extraFields().entrySet()) {
            String value = resolve(user, realm, field.getValue());
            if (value != null) {
                payload.put(field.getKey(), value);
            }
        }
        return payload;
    }

    /**
     * Sources are validated at startup and on console save, so an unknown spec here means the
     * stored config was edited by other means. Surface it as an outage rather than a stack trace.
     */
    private static String resolve(UserModel user, RealmModel realm, String spec) {
        try {
            return UserFieldResolver.resolve(user, realm, spec);
        } catch (IllegalArgumentException e) {
            throw new VerificationException("Invalid field source in configuration: " + spec, e);
        }
    }

    private HttpRequestBase buildPost(Map<String, String> payload) {
        HttpPost post = new HttpPost(config.endpoint());
        post.setHeader("Content-Type", "application/json");
        try {
            post.setEntity(
                    new StringEntity(
                            JsonSerialization.writeValueAsString(payload), StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new VerificationException("Could not serialise verification payload", e);
        }
        return post;
    }

    private HttpRequestBase buildGet(Map<String, String> payload) {
        try {
            URIBuilder builder = new URIBuilder(config.endpoint());
            payload.forEach(builder::addParameter);
            return new HttpGet(builder.build());
        } catch (URISyntaxException e) {
            throw new VerificationException("Invalid verification endpoint URL", e);
        }
    }

    private boolean parse(String body) {
        String trimmed = body == null ? "" : body.trim();
        if (trimmed.isEmpty()) {
            throw new VerificationException("Verification service returned an empty body");
        }
        try {
            JsonNode node = JsonSerialization.mapper.readTree(trimmed);
            if (node.isBoolean()) {
                return node.booleanValue();
            }
            String responseField = config.responseField();
            if (responseField != null && !responseField.isBlank()) {
                JsonNode explicit = node.at(toPointer(responseField));
                if (explicit.isBoolean()) {
                    return explicit.booleanValue();
                }
                throw new VerificationException(
                        "Response has no boolean at '" + responseField + "'");
            }
            for (String field : AUTO_DETECT_FIELDS) {
                JsonNode candidate = node.get(field);
                if (candidate != null && candidate.isBoolean()) {
                    return candidate.booleanValue();
                }
            }
        } catch (IOException e) {
            LOG.debugf(e, "Verification response was not JSON: %s", quotable(trimmed));
        }
        String lower = trimmed.toLowerCase(Locale.ROOT);
        if ("true".equals(lower) || "false".equals(lower)) {
            return "true".equals(lower);
        }
        throw new VerificationException("Unrecognised verification response: " + quotable(trimmed));
    }

    /** Accepts either "verified" or a JSON pointer such as "/data/verified". */
    private static String toPointer(String field) {
        return field.startsWith("/") ? field : "/" + field;
    }

    /**
     * Makes a foreign response body safe to quote in a log line or exception message. Allowlist:
     * only printable ASCII survives, every other character (line breaks, escape sequences, bidi
     * overrides, anything non-ASCII) becomes {@code ?}, so the body can neither forge log entries
     * nor confuse a terminal. Only a short prefix is kept, and only that prefix is scanned.
     */
    private static String quotable(String body) {
        int keep = Math.min(body.length(), MAX_QUOTED_BODY);
        StringBuilder out = new StringBuilder(keep + 24);
        for (int i = 0; i < keep; i++) {
            char c = body.charAt(i);
            out.append(c >= 0x20 && c <= 0x7E ? c : '?');
        }
        if (body.length() > keep) {
            out.append("... [").append(body.length()).append(" chars]");
        }
        return out.toString();
    }

    public static class VerificationException extends RuntimeException {
        public VerificationException(String message) {
            super(message);
        }

        public VerificationException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
