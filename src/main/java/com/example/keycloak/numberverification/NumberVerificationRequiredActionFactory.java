package com.example.keycloak.numberverification;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Map;
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

    @Override
    public void init(Config.Scope scope) {
        String endpoint = get(scope, VerificationConfig.ENDPOINT, "ENDPOINT", null);
        String methodRaw = get(scope, VerificationConfig.METHOD, "METHOD", "POST");
        String apiKey = get(scope, VerificationConfig.API_KEY, "API_KEY", null);
        String apiKeyHeader =
                get(scope, VerificationConfig.API_KEY_HEADER, "API_KEY_HEADER", "Authorization");

        String numberField = get(scope, VerificationConfig.NUMBER_FIELD, "NUMBER_FIELD", "number");
        String identifierSource =
                get(scope, VerificationConfig.IDENTIFIER_SOURCE, "IDENTIFIER_SOURCE", "id");
        String identifierField =
                get(
                        scope,
                        VerificationConfig.IDENTIFIER_FIELD,
                        "IDENTIFIER_FIELD",
                        UserFieldResolver.defaultFieldName(identifierSource));
        String extraRaw =
                get(scope, VerificationConfig.EXTRA_FIELDS, "EXTRA_FIELDS", "username,email,realm");
        String responseField =
                get(scope, VerificationConfig.RESPONSE_FIELD, "RESPONSE_FIELD", null);

        String storeAttribute =
                get(scope, VerificationConfig.STORE_ATTRIBUTE, "STORE_ATTRIBUTE", null);
        boolean enforceUnique =
                Boolean.parseBoolean(
                        get(scope, VerificationConfig.ENFORCE_UNIQUE, "ENFORCE_UNIQUE", "false"));
        int maxAttempts =
                VerificationConfig.parseInt(
                        get(scope, VerificationConfig.MAX_ATTEMPTS, "MAX_ATTEMPTS", "5"), 5);

        VerificationConfig.Method method =
                VerificationConfig.parseMethod(methodRaw, VerificationConfig.Method.POST);

        Map<String, String> extraFields = VerificationConfig.parseFieldList(extraRaw);
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
                        enforceUnique,
                        storeAttribute);

        if (endpoint == null || endpoint.isBlank()) {
            LOG.infof(
                    "No default verification endpoint set via %sENDPOINT; each realm must "
                            + "configure one in the admin console under Authentication -> "
                            + "Required actions -> %s.",
                    ENV_PREFIX, NumberVerificationRequiredAction.PROVIDER_ID);
        } else {
            LOG.infof("Default number verification endpoint: %s %s", method, endpoint);
        }
    }

    private String get(Config.Scope scope, String key, String envSuffix, String fallback) {
        String value = scope.get(key);
        if (value == null || value.isBlank()) {
            value = System.getenv(ENV_PREFIX + envSuffix);
        }
        return (value == null || value.isBlank()) ? fallback : value;
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
                        "Optional credential sent with each request. Stored in the realm "
                                + "configuration, so prefer the server-wide default for secrets.")
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
                .label("Max attempts")
                .helpText("Failed attempts before the login is aborted. 0 means unlimited.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue("5")
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
                .build();
    }

    /** Runs when an admin saves the form, so bad values are rejected at edit time. */
    @Override
    public void validateConfig(
            KeycloakSession session, RealmModel realm, RequiredActionConfigModel model) {
        RequiredActionFactory.super.validateConfig(session, realm, model);

        String endpoint = model.getConfigValue(VerificationConfig.ENDPOINT);
        if (endpoint != null && !endpoint.isBlank()) {
            try {
                URI uri = new URI(endpoint.trim());
                if (uri.getScheme() == null || uri.getHost() == null) {
                    throw new URISyntaxException(endpoint, "missing scheme or host");
                }
                if (!"http".equalsIgnoreCase(uri.getScheme())
                        && !"https".equalsIgnoreCase(uri.getScheme())) {
                    throw new ModelValidationException(
                            "Verification endpoint must use http or https");
                }
            } catch (URISyntaxException e) {
                throw new ModelValidationException("Verification endpoint is not a valid URL");
            }
        } else if (defaults.getEndpoint() == null || defaults.getEndpoint().isBlank()) {
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

        String maxAttempts = model.getConfigValue(VerificationConfig.MAX_ATTEMPTS);
        if (maxAttempts != null && !maxAttempts.isBlank()) {
            try {
                if (Integer.parseInt(maxAttempts.trim()) < 0) {
                    throw new ModelValidationException("Max attempts cannot be negative");
                }
            } catch (NumberFormatException e) {
                throw new ModelValidationException("Max attempts must be a whole number");
            }
        }

        boolean enforceUnique =
                Boolean.parseBoolean(model.getConfigValue(VerificationConfig.ENFORCE_UNIQUE));
        String storeAttribute = model.getConfigValue(VerificationConfig.STORE_ATTRIBUTE);
        if (enforceUnique
                && (storeAttribute == null || storeAttribute.isBlank())
                && (defaults.getStoreAttribute() == null
                        || defaults.getStoreAttribute().isBlank())) {
            throw new ModelValidationException(
                    "Enforcing local uniqueness requires 'Store number as attribute' to be set");
        }
    }

    private void validateSource(String spec, String label) {
        if (spec == null || spec.isBlank()) {
            return;
        }
        String s = spec.trim();
        if (s.regionMatches(
                true,
                0,
                UserFieldResolver.ATTR_PREFIX,
                0,
                UserFieldResolver.ATTR_PREFIX.length())) {
            if (s.substring(UserFieldResolver.ATTR_PREFIX.length()).isBlank()) {
                throw new ModelValidationException(label + ": 'attr:' needs an attribute name");
            }
            return;
        }
        if (!List.of("id", "userId", "username", "email", "firstName", "lastName", "realm")
                .contains(s)) {
            throw new ModelValidationException(
                    label
                            + ": unknown source '"
                            + spec
                            + "'. Use id, username, email, firstName, lastName, realm or"
                            + " attr:<name>.");
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
