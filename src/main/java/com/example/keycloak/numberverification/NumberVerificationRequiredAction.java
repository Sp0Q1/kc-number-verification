package com.example.keycloak.numberverification;

import jakarta.ws.rs.core.MultivaluedMap;
import org.jboss.logging.Logger;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.managers.BruteForceProtector;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Mandatory verification step: the user submits a number, we ask a backend REST API whether that
 * number is valid <em>for this specific account</em>, and only a {@code true} answer lets the login
 * continue.
 *
 * <p>Failed attempts are limited twice over. A per-login counter aborts the current login after
 * {@code maxAttempts}; on top of that every rejection is reported to Keycloak's brute-force
 * detector, so when the realm has brute-force protection enabled the user is locked out across
 * logins by the realm's own policy, just as with a wrong password or OTP.
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
     * Effective configuration for this realm: whatever the admin saved in the console, falling back
     * to the startup defaults for anything left blank.
     */
    private VerificationConfig configOf(RequiredActionContext context) {
        return VerificationConfig.resolve(defaults, context.getConfig());
    }

    /**
     * Runs on every authentication. New accounts already carry the action because the factory is
     * registered as a default action; with "apply to existing users" on, this also catches
     * pre-existing accounts that have never been verified.
     */
    @Override
    public void evaluateTriggers(RequiredActionContext context) {
        UserModel user = context.getUser();
        if (user == null || isVerified(user)) {
            return;
        }
        if (configOf(context).applyToExistingUsers()) {
            user.addRequiredAction(PROVIDER_ID);
        }
    }

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        if (isVerified(context.getUser())) {
            context.success();
            return;
        }
        context.challenge(form(context, configOf(context)).createForm(FORM_TEMPLATE));
    }

    @Override
    public void processAction(RequiredActionContext context) {
        MultivaluedMap<String, String> formData =
                context.getHttpRequest().getDecodedFormParameters();
        String raw = formData.getFirst(FORM_FIELD);
        String number = raw == null ? "" : raw.trim();

        KeycloakSession session = context.getSession();
        UserModel user = context.getUser();
        RealmModel realm = context.getRealm();
        VerificationConfig config = configOf(context);

        EventBuilder event =
                context.getEvent()
                        .clone()
                        .event(EventType.CUSTOM_REQUIRED_ACTION)
                        .detail(Details.CUSTOM_REQUIRED_ACTION, PROVIDER_ID);

        if (number.isEmpty()) {
            challengeWithFieldError(context, config, "numberVerificationMissing");
            return;
        }
        if (number.length() > config.maxLength()) {
            challengeWithFieldError(context, config, "numberVerificationTooLong");
            return;
        }

        BruteForceProtector protector = session.getProvider(BruteForceProtector.class);
        if (realm.isBruteForceProtected()
                && protector.isTemporarilyDisabled(session, realm, user)) {
            event.error(Errors.USER_TEMPORARILY_DISABLED);
            challengeWithError(context, config, "numberVerificationLocked");
            return;
        }

        // Optional local guard: refuse a number already bound to a different account.
        if (isClaimedByAnotherUser(session, realm, user, number, config)) {
            LOG.warnf(
                    "User %s submitted a number already bound to another account",
                    user.getUsername());
            recordFailedAttempt(context, protector);
            event.error("number_verification_already_used");
            challengeWithFieldError(context, config, "numberVerificationAlreadyUsed");
            return;
        }

        boolean verified;
        try {
            verified = new VerificationClient(config).verify(session, realm, user, number);
        } catch (VerificationClient.VerificationException e) {
            LOG.errorf(e, "Number verification failed for user %s", user.getUsername());
            event.error("number_verification_unavailable");
            // Fail closed: the user cannot proceed while the service is down.
            challengeWithError(context, config, "numberVerificationUnavailable");
            return;
        }

        if (!verified) {
            int attempts = recordFailedAttempt(context, protector);
            event.detail("attempts", String.valueOf(attempts))
                    .error("number_verification_rejected");

            if (config.maxAttempts() > 0 && attempts >= config.maxAttempts()) {
                LOG.warnf("User %s exhausted number verification attempts", user.getUsername());
                context.failure();
                return;
            }
            challengeWithFieldError(context, config, "numberVerificationInvalid");
            return;
        }

        user.setSingleAttribute(VERIFIED_ATTRIBUTE, "true");
        if (config.storesNumber()) {
            user.setSingleAttribute(config.storeAttribute(), number);
        }
        context.getAuthenticationSession().removeAuthNote(ATTEMPTS_NOTE);
        event.success();
        context.success();
    }

    private static boolean isVerified(UserModel user) {
        return Boolean.parseBoolean(user.getFirstAttribute(VERIFIED_ATTRIBUTE));
    }

    /**
     * Only meaningful when the verified number is stored as a user attribute. The backend remains
     * the authority; this just stops two local accounts sharing a number if the backend does not
     * enforce that itself.
     */
    private static boolean isClaimedByAnotherUser(
            KeycloakSession session,
            RealmModel realm,
            UserModel user,
            String number,
            VerificationConfig config) {
        if (!config.enforceUnique() || !config.storesNumber()) {
            return false;
        }
        return session.users()
                .searchForUserByUserAttributeStream(realm, config.storeAttribute(), number)
                .anyMatch(other -> !other.getId().equals(user.getId()));
    }

    /** Error shown inline under the number field. */
    private void challengeWithFieldError(
            RequiredActionContext context, VerificationConfig config, String messageKey) {
        context.challenge(
                form(context, config)
                        .addError(new FormMessage(FORM_FIELD, messageKey))
                        .createForm(FORM_TEMPLATE));
    }

    /** Error shown as a page-level alert, for conditions unrelated to what was typed. */
    private void challengeWithError(
            RequiredActionContext context, VerificationConfig config, String messageKey) {
        context.challenge(form(context, config).setError(messageKey).createForm(FORM_TEMPLATE));
    }

    private LoginFormsProvider form(RequiredActionContext context, VerificationConfig config) {
        return context.form()
                .setAttribute("username", context.getUser().getUsername())
                .setAttribute("maxLength", config.maxLength());
    }

    /**
     * Counts the failure for this login and, when the realm has brute-force protection enabled,
     * reports it to Keycloak so the realm's lockout policy applies across logins.
     *
     * @return failures so far in this login
     */
    private static int recordFailedAttempt(
            RequiredActionContext context, BruteForceProtector protector) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        int attempts = VerificationConfig.parseInt(authSession.getAuthNote(ATTEMPTS_NOTE), 0) + 1;
        authSession.setAuthNote(ATTEMPTS_NOTE, String.valueOf(attempts));

        RealmModel realm = context.getRealm();
        if (realm.isBruteForceProtected()) {
            protector.failedLogin(
                    realm, context.getUser(), context.getConnection(), context.getUriInfo(), null);
        }
        return attempts;
    }

    @Override
    public void close() {
        // nothing to release
    }
}
