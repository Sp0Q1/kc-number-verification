package com.example.keycloak.numberverification;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import org.keycloak.models.RequiredActionConfigModel;

/**
 * Configuration for the verification call.
 *
 * <p>Two layers: values parsed once at startup from environment variables / SPI options act as the
 * defaults, and each realm may override any of them through the admin console. {@link
 * #resolve(VerificationConfig, RequiredActionConfigModel)} merges the two.
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
        boolean enforceUnique,
        String storeAttribute,
        boolean applyToExistingUsers) {

    // Config keys - these are the property names shown in the admin console and used
    // by the Admin REST API.
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
    public static final String STORE_ATTRIBUTE = "storeAttribute";
    public static final String ENFORCE_UNIQUE = "enforceUnique";
    public static final String APPLY_TO_EXISTING_USERS = "applyToExistingUsers";

    public static final int DEFAULT_MAX_ATTEMPTS = 5;
    public static final int DEFAULT_MAX_LENGTH = 64;

    public enum Method {
        POST,
        GET
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
     * Overlays whatever the realm admin configured in the console onto the startup defaults. A
     * blank or absent console value leaves the default in place, so an existing
     * environment-variable deployment keeps working untouched.
     *
     * @param model the realm's stored config, or {@code null} if nothing has been saved
     */
    public static VerificationConfig resolve(
            VerificationConfig defaults, RequiredActionConfigModel model) {
        if (model == null) {
            return defaults;
        }

        String identifierSource = str(model, IDENTIFIER_SOURCE, defaults.identifierSource);
        String identifierField = str(model, IDENTIFIER_FIELD, null);
        if (identifierField == null) {
            // No explicit field name: keep the default only if the source is unchanged,
            // otherwise derive a sensible name from the new source.
            identifierField =
                    identifierSource.equals(defaults.identifierSource)
                            ? defaults.identifierField
                            : UserFieldResolver.defaultFieldName(identifierSource);
        }

        // An explicitly emptied list means "send nothing extra", which is different
        // from the key being absent.
        String extraRaw = model.getConfigValue(EXTRA_FIELDS);
        Map<String, String> extraFields =
                new LinkedHashMap<>(
                        extraRaw == null ? defaults.extraFields : parseFieldList(extraRaw));
        extraFields.remove(identifierField);

        return new VerificationConfig(
                str(model, ENDPOINT, defaults.endpoint),
                parseMethod(str(model, METHOD, null), defaults.method),
                str(model, API_KEY, defaults.apiKey),
                str(model, API_KEY_HEADER, defaults.apiKeyHeader),
                str(model, NUMBER_FIELD, defaults.numberField),
                identifierField,
                identifierSource,
                extraFields,
                str(model, RESPONSE_FIELD, defaults.responseField),
                parseInt(str(model, MAX_ATTEMPTS, null), defaults.maxAttempts),
                parseInt(str(model, MAX_LENGTH, null), defaults.maxLength),
                bool(model, ENFORCE_UNIQUE, defaults.enforceUnique),
                str(model, STORE_ATTRIBUTE, defaults.storeAttribute),
                bool(model, APPLY_TO_EXISTING_USERS, defaults.applyToExistingUsers));
    }

    private static String str(RequiredActionConfigModel model, String key, String fallback) {
        String value = model.getConfigValue(key);
        return isSet(value) ? value : fallback;
    }

    private static boolean bool(RequiredActionConfigModel model, String key, boolean fallback) {
        String value = str(model, key, null);
        return value == null ? fallback : Boolean.parseBoolean(value.trim());
    }

    private static boolean isSet(String value) {
        return value != null && !value.isBlank();
    }

    public static Method parseMethod(String raw, Method fallback) {
        if (!isSet(raw)) {
            return fallback;
        }
        try {
            return Method.valueOf(raw.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            return fallback;
        }
    }

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

    /**
     * Parses a spec list such as {@code "username,email,tenant=attr:tenantId"} into an ordered map
     * of JSON field name -> source spec.
     */
    public static Map<String, String> parseFieldList(String raw) {
        Map<String, String> result = new LinkedHashMap<>();
        if (!isSet(raw)) {
            return result;
        }
        for (String entry : raw.split(",")) {
            String item = entry.trim();
            if (item.isEmpty()) {
                continue;
            }
            int eq = item.indexOf('=');
            if (eq > 0) {
                String name = item.substring(0, eq).trim();
                String source = item.substring(eq + 1).trim();
                if (!name.isEmpty() && !source.isEmpty()) {
                    result.put(name, source);
                }
            } else {
                result.put(UserFieldResolver.defaultFieldName(item), item);
            }
        }
        return result;
    }
}
