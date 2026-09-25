package com.example.keycloak.numberverification;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.util.EntityUtils;
import org.jboss.logging.Logger;
import org.keycloak.connections.httpclient.HttpClientProvider;
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
 * <p>Requests go through Keycloak's shared {@link HttpClientProvider}, so connection pooling and
 * the server-wide socket timeout (5 s by default) apply without any extra configuration.
 */
public class VerificationClient {

    private static final Logger LOG = Logger.getLogger(VerificationClient.class);

    /** Longest slice of a backend response that may end up in a log line or event. */
    private static final int MAX_QUOTED_BODY = 200;

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
        LOG.debugf(
                "Verifying number for %s=%s",
                config.identifierField(), payload.get(config.identifierField()));

        HttpRequestBase request =
                config.method() == VerificationConfig.Method.GET
                        ? buildGet(payload)
                        : buildPost(payload);

        if (config.hasApiKey()) {
            request.setHeader(config.apiKeyHeader(), config.apiKey());
        }
        request.setHeader("Accept", "application/json");

        CloseableHttpClient http = session.getProvider(HttpClientProvider.class).getHttpClient();
        try (CloseableHttpResponse response = http.execute(request)) {
            int status = response.getStatusLine().getStatusCode();
            String body =
                    response.getEntity() == null
                            ? ""
                            : EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

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
            throw new VerificationException("Could not reach verification service", e);
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
            LOG.debugf(e, "Verification response was not JSON: %s", abbreviate(trimmed));
        }
        if ("true".equalsIgnoreCase(trimmed) || "false".equalsIgnoreCase(trimmed)) {
            return Boolean.parseBoolean(trimmed);
        }
        throw new VerificationException(
                "Unrecognised verification response: " + abbreviate(trimmed));
    }

    /** Accepts either "verified" or a JSON pointer such as "/data/verified". */
    private static String toPointer(String field) {
        return field.startsWith("/") ? field : "/" + field;
    }

    /** Keeps foreign response bodies out of the logs beyond what is needed to debug them. */
    private static String abbreviate(String body) {
        return body.length() <= MAX_QUOTED_BODY
                ? body
                : body.substring(0, MAX_QUOTED_BODY) + "... [" + body.length() + " chars]";
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
