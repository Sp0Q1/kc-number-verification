package com.example.keycloak.numberverification;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import org.keycloak.models.RequiredActionConfigModel;

/**
 * Configuration for the verification call.
 *
 * <p>Three layers: {@link #BUILT_IN} defaults, server-wide defaults parsed once at startup from SPI
 * options or environment variables, and per-realm overrides from the admin console. Every layer is
 * read through the same {@link #parse(Source, VerificationConfig)}, so one rule set applies no
 * matter where a value came from. A blank or absent value inherits from the layer below.
 */
public record VerificationConfig(
        String endpoint,
        Method method,
        String apiKey,
        String apiKeyHeader,
        String numberField,
        String identifierField,
        String identifierSource,
        Map<String, String> extraFields,
        String responseField,
        int maxAttempts,
        int maxLength,
        Pattern pattern,
        boolean enforceUnique,
        String storeAttribute,
        boolean applyToExistingUsers,
        boolean allowInsecureHttp) {

    // Config keys - these are the property names shown in the admin console and used
    // by the Admin REST API. The environment variable for each is NUMBER_VERIFICATION_
    // followed by the key in upper snake case.
    public static final String ENDPOINT = "endpoint";
    public static final String METHOD = "method";
    public static final String API_KEY = "apiKey";
    public static final String API_KEY_HEADER = "apiKeyHeader";
    public static final String NUMBER_FIELD = "numberField";
    public static final String IDENTIFIER_SOURCE = "identifierSource";
    public static final String IDENTIFIER_FIELD = "identifierField";
    public static final String EXTRA_FIELDS = "extraFields";
    public static final String RESPONSE_FIELD = "responseField";
    public static final String MAX_ATTEMPTS = "maxAttempts";
    public static final String MAX_LENGTH = "maxLength";
    public static final String PATTERN = "pattern";
    public static final String STORE_ATTRIBUTE = "storeAttribute";
    public static final String ENFORCE_UNIQUE = "enforceUnique";
    public static final String APPLY_TO_EXISTING_USERS = "applyToExistingUsers";
    public static final String ALLOW_INSECURE_HTTP = "allowInsecureHttp";

    public static final int DEFAULT_MAX_ATTEMPTS = 5;
    public static final int DEFAULT_MAX_LENGTH = 64;

    /** What applies when neither the server nor the realm says otherwise. */
    public static final VerificationConfig BUILT_IN =
            new VerificationConfig(
                    null,
                    Method.POST,
                    null,
                    "Authorization",
                    "number",
                    "userId",
                    "id",
                    Map.of(),
                    null,
                    DEFAULT_MAX_ATTEMPTS,
                    DEFAULT_MAX_LENGTH,
                    null,
                    false,
                    null,
                    false,
                    false);

    public enum Method {
        POST,
        GET
    }

    /** Where raw setting strings come from: the console model, or SPI options and env vars. */
    @FunctionalInterface
    public interface Source {
        String get(String key);
    }

    /** A value that cannot be parsed or breaks a rule. {@link #key()} names the setting. */
    public static final class InvalidSettingException extends RuntimeException {
        private final String key;

        public InvalidSettingException(String key, String message) {
            super(message);
            this.key = key;
        }

        public String key() {
            return key;
        }
    }

    public VerificationConfig {
        extraFields = Collections.unmodifiableMap(new LinkedHashMap<>(extraFields));
    }

    public boolean hasEndpoint() {
        return isSet(endpoint);
    }

    public boolean hasApiKey() {
        return isSet(apiKey);
    }

    public boolean storesNumber() {
        return isSet(storeAttribute);
    }

    /**
     * The realm's effective configuration: console values layered on the server-wide defaults.
     *
     * @param model the realm's stored config, or {@code null} if nothing has been saved
     * @throws InvalidSettingException if a stored value is invalid (possible after a realm import,
     *     which bypasses save-time validation)
     */
    public static VerificationConfig resolve(
            VerificationConfig defaults, RequiredActionConfigModel model) {
        return model == null ? defaults : parse(model::getConfigValue, defaults);
    }

    /**
     * Parses and validates one layer of settings on top of {@code defaults}. This is the only place
     * that knows the rules.
     *
     * @throws InvalidSettingException naming the key of the first offending value
     */
    public static VerificationConfig parse(Source source, VerificationConfig defaults) {
        Reader in = new Reader(source);

        boolean allowInsecureHttp = in.bool(ALLOW_INSECURE_HTTP, defaults.allowInsecureHttp);
        String endpoint = in.str(ENDPOINT, defaults.endpoint);
        if (endpoint != null) {
            checkUrl(endpoint, allowInsecureHttp);
        }

        String identifierSource = in.source(IDENTIFIER_SOURCE, defaults.identifierSource);
        String identifierField = in.str(IDENTIFIER_FIELD, null);
        if (identifierField == null) {
            // No explicit field name: keep the inherited one only if the source is unchanged,
            // otherwise derive a sensible name from the new source.
            identifierField =
                    identifierSource.equals(defaults.identifierSource)
                            ? defaults.identifierField
                            : UserFieldResolver.defaultFieldName(identifierSource);
        }
        Map<String, String> extraFields = in.fieldList(EXTRA_FIELDS, defaults.extraFields);
        extraFields.remove(identifierField);

        boolean enforceUnique = in.bool(ENFORCE_UNIQUE, defaults.enforceUnique);
        String storeAttribute = in.str(STORE_ATTRIBUTE, defaults.storeAttribute);
        if (enforceUnique && !isSet(storeAttribute)) {
            throw new InvalidSettingException(
                    ENFORCE_UNIQUE, "requires a 'store number as attribute' name");
        }

        return new VerificationConfig(
                endpoint,
                in.method(METHOD, defaults.method),
                in.str(API_KEY, defaults.apiKey),
                in.str(API_KEY_HEADER, defaults.apiKeyHeader),
                in.str(NUMBER_FIELD, defaults.numberField),
                identifierField,
                identifierSource,
                extraFields,
                in.str(RESPONSE_FIELD, defaults.responseField),
                in.integer(MAX_ATTEMPTS, defaults.maxAttempts, 0),
                in.integer(MAX_LENGTH, defaults.maxLength, 1),
                in.pattern(PATTERN, defaults.pattern),
                enforceUnique,
                storeAttribute,
                in.bool(APPLY_TO_EXISTING_USERS, defaults.applyToExistingUsers),
                allowInsecureHttp);
    }

    /**
     * An absolute https URL. Plain http is refused unless explicitly allowed, so a verification
     * secret or personal data cannot be sent in clear by a typo.
     */
    private static void checkUrl(String endpoint, boolean allowInsecureHttp) {
        URI uri;
        try {
            uri = new URI(endpoint);
        } catch (URISyntaxException e) {
            throw new InvalidSettingException(ENDPOINT, "is not a valid URL");
        }
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        if (uri.getHost() == null || !(scheme.equals("https") || scheme.equals("http"))) {
            throw new InvalidSettingException(ENDPOINT, "must be an absolute http(s) URL");
        }
        if (scheme.equals("http") && !allowInsecureHttp) {
            throw new InvalidSettingException(
                    ENDPOINT,
                    "uses plain http; use https or explicitly allow insecure http ("
                            + ALLOW_INSECURE_HTTP
                            + ")");
        }
    }

    /** Typed, validated reads from a {@link Source}; blank means "inherit". */
    private record Reader(Source source) {

        String str(String key, String fallback) {
            String value = source.get(key);
            return isSet(value) ? value.trim() : fallback;
        }

        boolean bool(String key, boolean fallback) {
            String raw = str(key, null);
            if (raw == null) {
                return fallback;
            }
            String lower = raw.toLowerCase(Locale.ROOT);
            if (lower.equals("true") || lower.equals("false")) {
                return lower.equals("true");
            }
            throw new InvalidSettingException(key, "must be true or false");
        }

        int integer(String key, int fallback, int min) {
            String raw = str(key, null);
            if (raw == null) {
                return fallback;
            }
            int value;
            try {
                value = Integer.parseInt(raw);
            } catch (NumberFormatException e) {
                throw new InvalidSettingException(key, "must be a whole number");
            }
            if (value < min) {
                throw new InvalidSettingException(key, "must be at least " + min);
            }
            return value;
        }

        Method method(String key, Method fallback) {
            String raw = str(key, null);
            if (raw == null) {
                return fallback;
            }
            try {
                return Method.valueOf(raw.toUpperCase(Locale.ROOT));
            } catch (IllegalArgumentException e) {
                throw new InvalidSettingException(key, "must be POST or GET");
            }
        }

        Pattern pattern(String key, Pattern fallback) {
            String raw = str(key, null);
            if (raw == null) {
                return fallback;
            }
            try {
                return Pattern.compile(raw);
            } catch (PatternSyntaxException e) {
                throw new InvalidSettingException(
                        key, "is not a valid regular expression: " + e.getDescription());
            }
        }

        String source(String key, String fallback) {
            String raw = str(key, null);
            if (raw == null) {
                return fallback;
            }
            try {
                return UserFieldResolver.validate(raw);
            } catch (IllegalArgumentException e) {
                throw new InvalidSettingException(key, e.getMessage());
            }
        }

        /**
         * A spec list such as {@code "username,email,tenant=attr:tenantId"} as an ordered map of
         * JSON field name to source spec.
         */
        Map<String, String> fieldList(String key, Map<String, String> fallback) {
            String raw = str(key, null);
            if (raw == null) {
                return new LinkedHashMap<>(fallback);
            }
            Map<String, String> result = new LinkedHashMap<>();
            for (String entry : raw.split(",")) {
                String item = entry.trim();
                if (item.isEmpty()) {
                    continue;
                }
                int eq = item.indexOf('=');
                String name = eq > 0 ? item.substring(0, eq).trim() : null;
                String spec = eq > 0 ? item.substring(eq + 1).trim() : item;
                try {
                    spec = UserFieldResolver.validate(spec);
                } catch (IllegalArgumentException e) {
                    throw new InvalidSettingException(
                            key, "entry '" + item + "' " + e.getMessage());
                }
                if (name != null && name.isEmpty()) {
                    throw new InvalidSettingException(
                            key, "entry '" + item + "' has no field name");
                }
                result.put(name != null ? name : UserFieldResolver.defaultFieldName(spec), spec);
            }
            return result;
        }
    }

    private static boolean isSet(String value) {
        return value != null && !value.isBlank();
    }

    /** Lenient integer parse for values that are not settings, such as auth-session notes. */
    public static int parseInt(String raw, int fallback) {
        if (!isSet(raw)) {
            return fallback;
        }
        try {
            return Integer.parseInt(raw.trim());
        } catch (NumberFormatException e) {
            return fallback;
        }
    }
}
