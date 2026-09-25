package com.example.keycloak.numberverification;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.ModelValidationException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RequiredActionConfigModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

public class NumberVerificationRequiredActionFactory implements RequiredActionFactory {

    private static final Logger LOG =
            Logger.getLogger(NumberVerificationRequiredActionFactory.class);

    private static final String ENV_PREFIX = "NUMBER_VERIFICATION_";

    /** Startup defaults; each realm can override any of these in the admin console. */
    private VerificationConfig defaults;

    /**
     * Reads the server-wide defaults. Anything malformed fails startup with a message naming the
     * variable, rather than surfacing as an error page on the first login.
     */
    @Override
    public void init(Config.Scope scope) {
        String endpoint = get(scope, VerificationConfig.ENDPOINT, "ENDPOINT", null);
        String methodRaw = get(scope, VerificationConfig.METHOD, "METHOD", "POST");
        String apiKey = get(scope, VerificationConfig.API_KEY, "API_KEY", null);
        String apiKeyHeader =
                get(scope, VerificationConfig.API_KEY_HEADER, "API_KEY_HEADER", "Authorization");

        String numberField = get(scope, VerificationConfig.NUMBER_FIELD, "NUMBER_FIELD", "number");
        String identifierSource =
                requireSource(
                        get(scope, VerificationConfig.IDENTIFIER_SOURCE, "IDENTIFIER_SOURCE", "id"),
                        "IDENTIFIER_SOURCE");
        String identifierField =
                get(
                        scope,
                        VerificationConfig.IDENTIFIER_FIELD,
                        "IDENTIFIER_FIELD",
                        UserFieldResolver.defaultFieldName(identifierSource));
        // Present-but-empty means "send nothing extra"; absent means the default list.
        String extraRaw = getRaw(scope, VerificationConfig.EXTRA_FIELDS, "EXTRA_FIELDS");
        if (extraRaw == null) {
            extraRaw = "username,email,realm";
        }
        String responseField =
                get(scope, VerificationConfig.RESPONSE_FIELD, "RESPONSE_FIELD", null);

        String storeAttribute =
                get(scope, VerificationConfig.STORE_ATTRIBUTE, "STORE_ATTRIBUTE", null);
        boolean enforceUnique =
                getBoolean(scope, VerificationConfig.ENFORCE_UNIQUE, "ENFORCE_UNIQUE", false);
        boolean applyToExistingUsers =
                getBoolean(
                        scope,
                        VerificationConfig.APPLY_TO_EXISTING_USERS,
                        "APPLY_TO_EXISTING_USERS",
                        true);
        int maxAttempts =
                getInt(
                        scope,
                        VerificationConfig.MAX_ATTEMPTS,
                        "MAX_ATTEMPTS",
                        VerificationConfig.DEFAULT_MAX_ATTEMPTS,
                        0);
        int maxLength =
                getInt(
                        scope,
                        VerificationConfig.MAX_LENGTH,
                        "MAX_LENGTH",
                        VerificationConfig.DEFAULT_MAX_LENGTH,
                        1);

        if (endpoint != null) {
            requireUrl(
                    endpoint,
                    () ->
                            new IllegalStateException(
                                    ENV_PREFIX + "ENDPOINT is not a valid http(s) URL"));
        }
        VerificationConfig.Method method = VerificationConfig.parseMethod(methodRaw, null);
        if (method == null) {
            throw new IllegalStateException(ENV_PREFIX + "METHOD must be POST or GET");
        }
        if (enforceUnique && (storeAttribute == null || storeAttribute.isBlank())) {
            throw new IllegalStateException(
                    ENV_PREFIX + "ENFORCE_UNIQUE=true requires " + ENV_PREFIX + "STORE_ATTRIBUTE");
        }

        Map<String, String> extraFields = VerificationConfig.parseFieldList(extraRaw);
        extraFields.values().forEach(spec -> requireSource(spec, "EXTRA_FIELDS"));
        extraFields.remove(identifierField);

        this.defaults =
                new VerificationConfig(
                        endpoint,
                        method,
                        apiKey,
                        apiKeyHeader,
                        numberField,
                        identifierField,
                        identifierSource,
                        extraFields,
                        responseField,
                        maxAttempts,
                        maxLength,
                        enforceUnique,
                        storeAttribute,
                        applyToExistingUsers);

        if (defaults.hasEndpoint()) {
            LOG.infof("Default number verification endpoint: %s %s", method, endpoint);
        } else {
            LOG.infof(
                    "No default verification endpoint set via %sENDPOINT; each realm must "
                            + "configure one in the admin console under Authentication -> "
                            + "Required actions -> %s.",
                    ENV_PREFIX, NumberVerificationRequiredAction.PROVIDER_ID);
        }
    }

    private static String get(Config.Scope scope, String key, String envSuffix, String fallback) {
        String value = getRaw(scope, key, envSuffix);
        return (value == null || value.isBlank()) ? fallback : value.trim();
    }

    /** SPI option first, then the environment variable; {@code null} only if neither is set. */
    private static String getRaw(Config.Scope scope, String key, String envSuffix) {
        String value = scope.get(key);
        return value != null ? value : System.getenv(ENV_PREFIX + envSuffix);
    }

    private static boolean getBoolean(
            Config.Scope scope, String key, String envSuffix, boolean fallback) {
        String raw = get(scope, key, envSuffix, null);
        if (raw == null) {
            return fallback;
        }
        if (raw.equalsIgnoreCase("true") || raw.equalsIgnoreCase("false")) {
            return Boolean.parseBoolean(raw);
        }
        throw new IllegalStateException(ENV_PREFIX + envSuffix + " must be true or false");
    }

    private static int getInt(
            Config.Scope scope, String key, String envSuffix, int fallback, int min) {
        String raw = get(scope, key, envSuffix, null);
        if (raw == null) {
            return fallback;
        }
        try {
            int value = Integer.parseInt(raw);
            if (value < min) {
                throw new IllegalStateException(
                        ENV_PREFIX + envSuffix + " must be at least " + min);
            }
            return value;
        } catch (NumberFormatException e) {
            throw new IllegalStateException(ENV_PREFIX + envSuffix + " must be a whole number", e);
        }
    }

    private static String requireSource(String spec, String envSuffix) {
        try {
            return UserFieldResolver.validate(spec);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException(ENV_PREFIX + envSuffix + ": " + e.getMessage(), e);
        }
    }

    private static void requireUrl(String endpoint, Supplier<? extends RuntimeException> error) {
        try {
            URI uri = new URI(endpoint.trim());
            boolean http =
                    "http".equalsIgnoreCase(uri.getScheme())
                            || "https".equalsIgnoreCase(uri.getScheme());
            if (!http || uri.getHost() == null) {
                throw error.get();
            }
        } catch (URISyntaxException e) {
            throw error.get();
        }
    }

    // ---------------------------------------------------------------- admin console

    /** Puts a settings gear next to this action in Authentication -> Required actions. */
    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public List<ProviderConfigProperty> getConfigMetadata() {
        return ProviderConfigurationBuilder.create()
                .property()
                .name(VerificationConfig.ENDPOINT)
                .label("Verification endpoint")
                .helpText(
                        "Full URL of the REST API that verifies a number for an account. "
                                + "Leave blank to use the server-wide default.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property()
                .name(VerificationConfig.METHOD)
                .label("HTTP method")
                .helpText("POST sends a JSON body; GET sends query parameters.")
                .type(ProviderConfigProperty.LIST_TYPE)
                .options("POST", "GET")
                .defaultValue("POST")
                .add()
                .property()
                .name(VerificationConfig.API_KEY)
                .label("API key")
                .helpText(
                        "Optional credential sent verbatim in the header below (include any "
                                + "'Bearer ' prefix yourself). Stored in the realm configuration, "
                                + "so prefer the server-wide default for secrets.")
                .type(ProviderConfigProperty.PASSWORD)
                .secret(true)
                .add()
                .property()
                .name(VerificationConfig.API_KEY_HEADER)
                .label("API key header")
                .helpText("Header the API key is sent in. Defaults to Authorization.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue("Authorization")
                .add()
                .property()
                .name(VerificationConfig.IDENTIFIER_SOURCE)
                .label("Account identifier source")
                .helpText(
                        "Which user property identifies the account to the backend: "
                                + "id, username, email, firstName, lastName, realm, or "
                                + "attr:<name> for a custom user attribute. 'id' is the Keycloak "
                                + "UUID and is the safest choice - it never changes.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue("id")
                .add()
                .property()
                .name(VerificationConfig.IDENTIFIER_FIELD)
                .label("Account identifier field name")
                .helpText(
                        "JSON/query field the identifier is sent under. Derived from the "
                                + "source if left blank.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property()
                .name(VerificationConfig.NUMBER_FIELD)
                .label("Number field name")
                .helpText("JSON/query field the submitted number is sent under.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue("number")
                .add()
                .property()
                .name(VerificationConfig.EXTRA_FIELDS)
                .label("Additional fields")
                .helpText(
                        "Comma-separated extra fields to send, e.g. "
                                + "username,email,tenant=attr:tenantId. Same source syntax as the "
                                + "identifier.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property()
                .name(VerificationConfig.RESPONSE_FIELD)
                .label("Response field")
                .helpText(
                        "Field holding the boolean result, or a JSON pointer such as "
                                + "/data/verified. Left blank, common names are auto-detected.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property()
                .name(VerificationConfig.MAX_ATTEMPTS)
                .label("Max attempts per login")
                .helpText(
                        "Failed attempts before the current login is aborted. 0 means unlimited. "
                                + "Every failure is also reported to the realm's brute-force "
                                + "detection, which enforces lockout across logins when enabled.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(String.valueOf(VerificationConfig.DEFAULT_MAX_ATTEMPTS))
                .add()
                .property()
                .name(VerificationConfig.MAX_LENGTH)
                .label("Max number length")
                .helpText("Longest input accepted from the form, in characters.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(String.valueOf(VerificationConfig.DEFAULT_MAX_LENGTH))
                .add()
                .property()
                .name(VerificationConfig.STORE_ATTRIBUTE)
                .label("Store number as attribute")
                .helpText(
                        "If set, the verified number is saved on the user under this "
                                + "attribute name. Leave blank if the number is sensitive - it is "
                                + "stored in clear text.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property()
                .name(VerificationConfig.ENFORCE_UNIQUE)
                .label("Enforce local uniqueness")
                .helpText(
                        "Reject a number already stored against another account in this "
                                + "realm. Requires 'Store number as attribute'.")
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue("false")
                .add()
                .property()
                .name(VerificationConfig.APPLY_TO_EXISTING_USERS)
                .label("Apply to existing users")
                .helpText(
                        "On: every account that has not been verified is asked at its next login. "
                                + "Off: only accounts created after this action was made a default "
                                + "action are asked.")
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue("true")
                .add()
                .build();
    }

    /** Runs when an admin saves the form, so bad values are rejected at edit time. */
    @Override
    public void validateConfig(
            KeycloakSession session, RealmModel realm, RequiredActionConfigModel model) {
        RequiredActionFactory.super.validateConfig(session, realm, model);

        String endpoint = model.getConfigValue(VerificationConfig.ENDPOINT);
        if (endpoint != null && !endpoint.isBlank()) {
            requireUrl(
                    endpoint,
                    () ->
                            new ModelValidationException(
                                    "Verification endpoint must be a valid http or https URL"));
        } else if (!defaults.hasEndpoint()) {
            throw new ModelValidationException(
                    "A verification endpoint is required: no "
                            + "server-wide default is configured for this server");
        }

        String method = model.getConfigValue(VerificationConfig.METHOD);
        if (method != null
                && !method.isBlank()
                && VerificationConfig.parseMethod(method, null) == null) {
            throw new ModelValidationException("HTTP method must be POST or GET");
        }

        validateSource(
                model.getConfigValue(VerificationConfig.IDENTIFIER_SOURCE),
                "Account identifier source");
        String extras = model.getConfigValue(VerificationConfig.EXTRA_FIELDS);
        if (extras != null && !extras.isBlank()) {
            VerificationConfig.parseFieldList(extras)
                    .values()
                    .forEach(spec -> validateSource(spec, "Additional fields"));
        }

        validateInt(model.getConfigValue(VerificationConfig.MAX_ATTEMPTS), "Max attempts", 0);
        validateInt(model.getConfigValue(VerificationConfig.MAX_LENGTH), "Max number length", 1);

        boolean enforceUnique =
                Boolean.parseBoolean(model.getConfigValue(VerificationConfig.ENFORCE_UNIQUE));
        String storeAttribute = model.getConfigValue(VerificationConfig.STORE_ATTRIBUTE);
        if (enforceUnique
                && (storeAttribute == null || storeAttribute.isBlank())
                && !defaults.storesNumber()) {
            throw new ModelValidationException(
                    "Enforcing local uniqueness requires 'Store number as attribute' to be set");
        }
    }

    private static void validateSource(String spec, String label) {
        if (spec == null || spec.isBlank()) {
            return;
        }
        try {
            UserFieldResolver.validate(spec);
        } catch (IllegalArgumentException e) {
            throw new ModelValidationException(label + ": " + e.getMessage());
        }
    }

    private static void validateInt(String raw, String label, int min) {
        if (raw == null || raw.isBlank()) {
            return;
        }
        try {
            if (Integer.parseInt(raw.trim()) < min) {
                throw new ModelValidationException(label + " must be at least " + min);
            }
        } catch (NumberFormatException e) {
            throw new ModelValidationException(label + " must be a whole number");
        }
    }

    // ---------------------------------------------------------------- lifecycle

    @Override
    public RequiredActionProvider create(KeycloakSession session) {
        return new NumberVerificationRequiredAction(defaults);
    }

    @Override
    public String getId() {
        return NumberVerificationRequiredAction.PROVIDER_ID;
    }

    @Override
    public String getDisplayText() {
        return "Verify Number";
    }

    /** The action is removed from the user once it completes successfully. */
    @Override
    public boolean isOneTimeAction() {
        return true;
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // no-op
    }

    @Override
    public void close() {
        // no-op
    }
}
