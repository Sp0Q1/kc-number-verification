package com.example.keycloak.numberverification;

import java.util.List;
import java.util.Locale;
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
     * Reads the server-wide defaults from SPI options or environment variables. Anything malformed
     * fails startup with a message naming the variable, rather than surfacing on the first login.
     */
    @Override
    public void init(Config.Scope scope) {
        try {
            defaults =
                    VerificationConfig.parse(
                            key -> {
                                String value = scope.get(key);
                                return value != null ? value : System.getenv(envName(key));
                            },
                            VerificationConfig.BUILT_IN);
        } catch (VerificationConfig.InvalidSettingException e) {
            throw new IllegalStateException(envName(e.key()) + " " + e.getMessage(), e);
        }

        if (defaults.hasEndpoint()) {
            LOG.infof(
                    "Default number verification endpoint: %s %s",
                    defaults.method(), defaults.endpoint());
        } else {
            LOG.infof(
                    "No default verification endpoint set via %s; each realm must configure one in"
                            + " the admin console under Authentication -> Required actions -> %s.",
                    envName(VerificationConfig.ENDPOINT),
                    NumberVerificationRequiredAction.PROVIDER_ID);
        }
    }

    /** {@code apiKeyHeader} becomes {@code NUMBER_VERIFICATION_API_KEY_HEADER}. */
    static String envName(String key) {
        return ENV_PREFIX + key.replaceAll("([a-z])([A-Z])", "$1_$2").toUpperCase(Locale.ROOT);
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
                                + "identifier. Nothing beyond the identifier is sent by default.")
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
                .name(VerificationConfig.PATTERN)
                .label("Number pattern")
                .helpText(
                        "Optional regular expression the whole input must match, e.g. [0-9]{6,12}. "
                                + "Rejected input never reaches the backend.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property()
                .name(VerificationConfig.ALLOW_INSECURE_HTTP)
                .label("Allow plain http endpoint")
                .helpText(
                        "Off: the endpoint must be https. Turn on only for local testing or a "
                                + "trusted private network.")
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue("false")
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

    /**
     * Runs when an admin saves the form. The same rules as at startup; errors are phrased with the
     * label the admin sees in the console.
     */
    @Override
    public void validateConfig(
            KeycloakSession session, RealmModel realm, RequiredActionConfigModel model) {
        RequiredActionFactory.super.validateConfig(session, realm, model);
        VerificationConfig effective;
        try {
            effective = VerificationConfig.parse(model::getConfigValue, defaults);
        } catch (VerificationConfig.InvalidSettingException e) {
            throw new ModelValidationException(label(e.key()) + " " + e.getMessage());
        }
        if (!effective.hasEndpoint()) {
            throw new ModelValidationException(
                    "A verification endpoint is required: no server-wide default is configured");
        }
    }

    private String label(String key) {
        return getConfigMetadata().stream()
                .filter(property -> key.equals(property.getName()))
                .map(ProviderConfigProperty::getLabel)
                .findFirst()
                .orElse(key);
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
