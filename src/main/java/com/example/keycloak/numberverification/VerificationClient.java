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
 */
public class VerificationClient {

    private static final Logger LOG = Logger.getLogger(VerificationClient.class);

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
        if (config.getEndpoint() == null || config.getEndpoint().isBlank()) {
            throw new VerificationException("No verification endpoint configured");
        }

        Map<String, String> payload = buildPayload(realm, user, number);
        LOG.debugf(
                "Verifying number for %s=%s",
                config.getIdentifierField(), payload.get(config.getIdentifierField()));

        HttpRequestBase request =
                config.getMethod() == VerificationConfig.Method.GET
                        ? buildGet(payload)
                        : buildPost(payload);

        if (config.getApiKey() != null && !config.getApiKey().isBlank()) {
            request.setHeader(config.getApiKeyHeader(), config.getApiKey());
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
        payload.put(config.getNumberField(), number);

        String identifier = UserFieldResolver.resolve(user, realm, config.getIdentifierSource());
        if (identifier == null || identifier.isBlank()) {
            throw new VerificationException(
                    "Account identifier '"
                            + config.getIdentifierSource()
                            + "' is empty for user "
                            + user.getId()
                            + "; the backend cannot tell which account this number is for");
        }
        payload.put(config.getIdentifierField(), identifier);

        for (Map.Entry<String, String> field : config.getExtraFields().entrySet()) {
            String value = UserFieldResolver.resolve(user, realm, field.getValue());
            if (value != null) {
                payload.put(field.getKey(), value);
            }
        }
        return payload;
    }

    private HttpRequestBase buildPost(Map<String, String> payload) {
        HttpPost post = new HttpPost(config.getEndpoint());
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
            URIBuilder builder = new URIBuilder(config.getEndpoint());
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
            if (config.getResponseField() != null && !config.getResponseField().isBlank()) {
                JsonNode explicit = node.at(toPointer(config.getResponseField()));
                if (explicit.isBoolean()) {
                    return explicit.booleanValue();
                }
                throw new VerificationException(
                        "Response has no boolean at '" + config.getResponseField() + "'");
            }
            for (String field : new String[] {"verified", "valid", "result", "success"}) {
                JsonNode candidate = node.get(field);
                if (candidate != null && candidate.isBoolean()) {
                    return candidate.booleanValue();
                }
            }
        } catch (IOException e) {
            LOG.debugf(e, "Verification response was not JSON: %s", trimmed);
        }
        if ("true".equalsIgnoreCase(trimmed) || "false".equalsIgnoreCase(trimmed)) {
            return Boolean.parseBoolean(trimmed);
        }
        throw new VerificationException("Unrecognised verification response: " + trimmed);
    }

    /** Accepts either "verified" or a JSON pointer such as "/data/verified". */
    private String toPointer(String field) {
        return field.startsWith("/") ? field : "/" + field;
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
