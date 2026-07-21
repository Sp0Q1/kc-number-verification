package com.example.keycloak.numberverification;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.events.Details;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Mandatory verification step: the user submits a number, we ask a backend REST API
 * whether that number is valid <em>for this specific account</em>, and only a
 * {@code true} answer lets the login continue.
 */
public class NumberVerificationRequiredAction implements RequiredActionProvider {

    private static final Logger LOG = Logger.getLogger(NumberVerificationRequiredAction.class);

    public static final String PROVIDER_ID = "verify-number";
    /** Set on the user once verification succeeds, so it never runs twice. */
    public static final String VERIFIED_ATTRIBUTE = "numberVerified";

    private static final String FORM_FIELD = "number";
    private static final String FORM_TEMPLATE = "number-verification.ftl";
    private static final String ATTEMPTS_NOTE = "number-verification-attempts";

    /** Server-wide defaults; per-realm overrides are layered on at request time. */
    private final VerificationConfig defaults;

    public NumberVerificationRequiredAction(VerificationConfig defaults) {
        this.defaults = defaults;
    }

    /**
     * Effective configuration for this realm: whatever the admin saved in the console,
     * falling back to the startup defaults for anything left blank.
     */
    private VerificationConfig configOf(RequiredActionContext context) {
        return VerificationConfig.resolve(defaults, context.getConfig());
    }

    /**
     * Runs on every authentication. New accounts already carry the action because the
     * factory is registered as a default action; this also catches pre-existing users
     * who have never been verified.
     */
    @Override
    public void evaluateTriggers(RequiredActionContext context) {
        UserModel user = context.getUser();
        if (user == null) {
            return;
        }
        if (!Boolean.parseBoolean(user.getFirstAttribute(VERIFIED_ATTRIBUTE))) {
            user.addRequiredAction(PROVIDER_ID);
        }
    }

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        if (Boolean.parseBoolean(context.getUser().getFirstAttribute(VERIFIED_ATTRIBUTE))) {
            context.success();
            return;
        }
        context.challenge(form(context).createForm(FORM_TEMPLATE));
    }

    @Override
    public void processAction(RequiredActionContext context) {
        MultivaluedMap<String, String> formData =
                context.getHttpRequest().getDecodedFormParameters();
        String number = formData.getFirst(FORM_FIELD);

        UserModel user = context.getUser();
        RealmModel realm = context.getRealm();
        VerificationConfig config = configOf(context);

        EventBuilder event = context.getEvent().clone()
                .event(EventType.CUSTOM_REQUIRED_ACTION)
                .detail(Details.CUSTOM_REQUIRED_ACTION, PROVIDER_ID);

        if (number == null || number.trim().isEmpty()) {
            challengeWithError(context, "numberVerificationMissing");
            return;
        }
        number = number.trim();

        // Optional local guard: refuse a number already bound to a different account.
        if (isClaimedByAnotherUser(context.getSession(), realm, user, number, config)) {
            LOG.warnf("User %s submitted a number already bound to another account",
                    user.getUsername());
            recordFailedAttempt(context.getAuthenticationSession());
            event.error("number_verification_already_used");
            challengeWithError(context, "numberVerificationAlreadyUsed");
            return;
        }

        boolean verified;
        try {
            verified = new VerificationClient(config)
                    .verify(context.getSession(), realm, user, number);
        } catch (VerificationClient.VerificationException e) {
            LOG.errorf(e, "Number verification failed for user %s", user.getUsername());
            event.error("number_verification_unavailable");
            // Fail closed: the user cannot proceed while the service is down.
            challengeWithError(context, "numberVerificationUnavailable");
            return;
        }

        if (!verified) {
            int attempts = recordFailedAttempt(context.getAuthenticationSession());
            event.detail("attempts", String.valueOf(attempts)).error("number_verification_rejected");

            if (config.getMaxAttempts() > 0 && attempts >= config.getMaxAttempts()) {
                LOG.warnf("User %s exhausted number verification attempts", user.getUsername());
                context.failure();
                return;
            }
            challengeWithError(context, "numberVerificationInvalid");
            return;
        }

        user.setSingleAttribute(VERIFIED_ATTRIBUTE, "true");
        if (config.getStoreAttribute() != null && !config.getStoreAttribute().isBlank()) {
            user.setSingleAttribute(config.getStoreAttribute(), number);
        }
        context.getAuthenticationSession().removeAuthNote(ATTEMPTS_NOTE);
        event.success();
        context.success();
    }

    /**
     * Only meaningful when the verified number is stored as a user attribute. The
     * backend remains the authority; this just stops two local accounts sharing a number
     * if the backend does not enforce that itself.
     */
    private boolean isClaimedByAnotherUser(KeycloakSession session, RealmModel realm,
                                           UserModel user, String number,
                                           VerificationConfig config) {
        String attribute = config.getStoreAttribute();
        if (!config.isEnforceUnique() || attribute == null || attribute.isBlank()) {
            return false;
        }
        return session.users()
                .searchForUserByUserAttributeStream(realm, attribute, number)
                .anyMatch(other -> !other.getId().equals(user.getId()));
    }

    private void challengeWithError(RequiredActionContext context, String messageKey) {
        Response challenge = form(context)
                .setError(messageKey)
                .createForm(FORM_TEMPLATE);
        context.challenge(challenge);
    }

    private LoginFormsProvider form(RequiredActionContext context) {
        return context.form()
                .setAttribute("username", context.getUser().getUsername());
    }

    private int recordFailedAttempt(AuthenticationSessionModel authSession) {
        int attempts = 0;
        String note = authSession.getAuthNote(ATTEMPTS_NOTE);
        if (note != null) {
            try {
                attempts = Integer.parseInt(note);
            } catch (NumberFormatException ignored) {
                // treat as zero
            }
        }
        attempts++;
        authSession.setAuthNote(ATTEMPTS_NOTE, String.valueOf(attempts));
        return attempts;
    }

    @Override
    public void close() {
        // nothing to release
    }
}
