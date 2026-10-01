package com.example.keycloak.numberverification;

import jakarta.ws.rs.core.UriInfo;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import org.jboss.logging.Logger;
import org.keycloak.common.ClientConnection;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.BruteForceProtector;

/**
 * Reports a failed verification to Keycloak's brute-force detector.
 *
 * <p>{@link BruteForceProtector#failedLogin} changed signature in 26.0 (added {@code UriInfo}),
 * 26.6 (added a {@code String} category) and 26.7 (category became a {@code Set}). A direct call
 * compiles against one of them and throws {@link NoSuchMethodError} on the others, so the overload
 * is resolved once at class load against whatever server this JAR runs on. The category is passed
 * as {@code null}, which every variant treats as "not category-scoped", exactly as Keycloak's own
 * {@code AuthenticationProcessor} does when none applies.
 */
final class BruteForceReporter {

    private static final Logger LOG = Logger.getLogger(BruteForceReporter.class);

    /** Newest first; the first one the running server provides is used. */
    private static final List<Class<?>[]> SIGNATURES =
            List.of(
                    new Class<?>[] {
                        RealmModel.class,
                        UserModel.class,
                        ClientConnection.class,
                        UriInfo.class,
                        Set.class
                    },
                    new Class<?>[] {
                        RealmModel.class,
                        UserModel.class,
                        ClientConnection.class,
                        UriInfo.class,
                        String.class
                    },
                    new Class<?>[] {
                        RealmModel.class, UserModel.class, ClientConnection.class, UriInfo.class
                    },
                    new Class<?>[] {RealmModel.class, UserModel.class, ClientConnection.class});

    private static final Method FAILED_LOGIN = resolve();

    private BruteForceReporter() {}

    private static Method resolve() {
        for (Class<?>[] signature : SIGNATURES) {
            try {
                return BruteForceProtector.class.getMethod("failedLogin", signature);
            } catch (NoSuchMethodException e) {
                // try the next older variant
            }
        }
        LOG.warn(
                "BruteForceProtector.failedLogin has an unknown signature on this Keycloak; "
                        + "failed number verifications will not count towards brute-force lockout");
        return null;
    }

    /** Which overload is in use, for diagnostics and tests. */
    static String resolvedSignature() {
        return FAILED_LOGIN == null
                ? "none"
                : Arrays.stream(FAILED_LOGIN.getParameterTypes())
                        .map(Class::getSimpleName)
                        .reduce((a, b) -> a + "," + b)
                        .orElse("");
    }

    /** No-op unless the realm has brute-force detection enabled. */
    static void failedLogin(
            KeycloakSession session,
            RealmModel realm,
            UserModel user,
            ClientConnection connection,
            UriInfo uriInfo) {
        if (!realm.isBruteForceProtected() || FAILED_LOGIN == null) {
            return;
        }
        BruteForceProtector protector = session.getProvider(BruteForceProtector.class);
        if (protector == null) {
            return;
        }
        Object[] args = {realm, user, connection, uriInfo, null};
        try {
            FAILED_LOGIN.invoke(protector, Arrays.copyOf(args, FAILED_LOGIN.getParameterCount()));
        } catch (IllegalAccessException | InvocationTargetException e) {
            Throwable cause = e instanceof InvocationTargetException ite ? ite.getCause() : e;
            LOG.warnf(cause, "Could not report a failed verification to brute-force detection");
        }
    }

    static boolean isTemporarilyDisabled(
            KeycloakSession session, RealmModel realm, UserModel user) {
        if (!realm.isBruteForceProtected()) {
            return false;
        }
        BruteForceProtector protector = session.getProvider(BruteForceProtector.class);
        return protector != null && protector.isTemporarilyDisabled(session, realm, user);
    }
}
