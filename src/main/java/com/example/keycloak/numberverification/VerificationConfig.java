package com.example.keycloak.numberverification;

import org.keycloak.models.RequiredActionConfigModel;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Configuration for the verification call.
 *
 * <p>Two layers: values parsed once at startup from environment variables / SPI options
 * act as the defaults, and each realm may override any of them through the admin
 * console. {@link #resolve(VerificationConfig, RequiredActionConfigModel)} merges the two.
 */
public class VerificationConfig {

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
    public static final String STORE_ATTRIBUTE = "storeAttribute";
    public static final String ENFORCE_UNIQUE = "enforceUnique";

    public enum Method { POST, GET }

    private final String endpoint;
    private final Method method;
    private final String apiKey;
    private final String apiKeyHeader;
    private final String numberField;
    private final String identifierField;
    private final String identifierSource;
    private final Map<String, String> extraFields;
    private final String responseField;
    private final int maxAttempts;
    private final boolean enforceUnique;
    private final String storeAttribute;

    public VerificationConfig(String endpoint, Method method, String apiKey, String apiKeyHeader,
                              String numberField, String identifierField, String identifierSource,
                              Map<String, String> extraFields, String responseField,
                              int maxAttempts, boolean enforceUnique, String storeAttribute) {
        this.endpoint = endpoint;
        this.method = method;
        this.apiKey = apiKey;
        this.apiKeyHeader = apiKeyHeader;
        this.numberField = numberField;
        this.identifierField = identifierField;
        this.identifierSource = identifierSource;
        this.extraFields = Collections.unmodifiableMap(new LinkedHashMap<>(extraFields));
        this.responseField = responseField;
        this.maxAttempts = maxAttempts;
        this.enforceUnique = enforceUnique;
        this.storeAttribute = storeAttribute;
    }

    /**
     * Overlays whatever the realm admin configured in the console onto the startup
     * defaults. A blank or absent console value leaves the default in place, so an
     * existing environment-variable deployment keeps working untouched.
     *
     * @param model the realm's stored config, or {@code null} if nothing has been saved
     */
    public static VerificationConfig resolve(VerificationConfig defaults,
                                             RequiredActionConfigModel model) {
        if (model == null) {
            return defaults;
        }

        String endpoint = str(model, ENDPOINT, defaults.endpoint);
        String apiKey = str(model, API_KEY, defaults.apiKey);
        String apiKeyHeader = str(model, API_KEY_HEADER, defaults.apiKeyHeader);
        String numberField = str(model, NUMBER_FIELD, defaults.numberField);
        String responseField = str(model, RESPONSE_FIELD, defaults.responseField);
        String storeAttribute = str(model, STORE_ATTRIBUTE, defaults.storeAttribute);

        Method method = parseMethod(str(model, METHOD, null), defaults.method);
        int maxAttempts = parseInt(str(model, MAX_ATTEMPTS, null), defaults.maxAttempts);

        String enforceRaw = str(model, ENFORCE_UNIQUE, null);
        boolean enforceUnique = enforceRaw == null
                ? defaults.enforceUnique
                : Boolean.parseBoolean(enforceRaw);

        String identifierSource = str(model, IDENTIFIER_SOURCE, defaults.identifierSource);
        String identifierField = str(model, IDENTIFIER_FIELD, null);
        if (identifierField == null) {
            // No explicit field name: keep the default only if the source is unchanged,
            // otherwise derive a sensible name from the new source.
            identifierField = identifierSource.equals(defaults.identifierSource)
                    ? defaults.identifierField
                    : UserFieldResolver.defaultFieldName(identifierSource);
        }

        // An explicitly emptied list means "send nothing extra", which is different
        // from the key being absent.
        String extraRaw = raw(model, EXTRA_FIELDS);
        Map<String, String> extraFields = extraRaw == null
                ? defaults.extraFields
                : parseFieldList(extraRaw);
        extraFields = new LinkedHashMap<>(extraFields);
        extraFields.remove(identifierField);

        return new VerificationConfig(endpoint, method, apiKey, apiKeyHeader, numberField,
                identifierField, identifierSource, extraFields, responseField,
                maxAttempts, enforceUnique, storeAttribute);
    }

    /**
     * Reads a single value from the stored realm config.
     *
     * <p>Note: if this fails to compile on your Keycloak version, swap it for
     * {@code model.getConfig().get(key)} - the accessor was introduced alongside
     * configurable required actions in Keycloak 25.
     */
    private static String raw(RequiredActionConfigModel model, String key) {
        return model.getConfigValue(key);
    }

    private static String str(RequiredActionConfigModel model, String key, String fallback) {
        String value = model.getConfigValue(key);
        return (value == null || value.isBlank()) ? fallback : value;
    }

    public static Method parseMethod(String raw, Method fallback) {
        if (raw == null || raw.isBlank()) {
            return fallback;
        }
        try {
            return Method.valueOf(raw.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            return fallback;
        }
    }

    public static int parseInt(String raw, int fallback) {
        if (raw == null || raw.isBlank()) {
            return fallback;
        }
        try {
            return Integer.parseInt(raw.trim());
        } catch (NumberFormatException e) {
            return fallback;
        }
    }

    /**
     * Parses a spec list such as {@code "username,email,tenant=attr:tenantId"} into an
     * ordered map of JSON field name -> source spec.
     */
    public static Map<String, String> parseFieldList(String raw) {
        Map<String, String> result = new LinkedHashMap<>();
        if (raw == null || raw.isBlank()) {
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

    public String getEndpoint() {
        return endpoint;
    }

    public Method getMethod() {
        return method;
    }

    public String getApiKey() {
        return apiKey;
    }

    public String getApiKeyHeader() {
        return apiKeyHeader;
    }

    public String getNumberField() {
        return numberField;
    }

    public String getIdentifierField() {
        return identifierField;
    }

    public String getIdentifierSource() {
        return identifierSource;
    }

    public Map<String, String> getExtraFields() {
        return extraFields;
    }

    public String getResponseField() {
        return responseField;
    }

    public int getMaxAttempts() {
        return maxAttempts;
    }

    public boolean isEnforceUnique() {
        return enforceUnique;
    }

    public String getStoreAttribute() {
        return storeAttribute;
    }
}
