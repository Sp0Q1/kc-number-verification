package com.example.keycloak.numberverification;

import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * Turns a configuration "source spec" into a concrete value taken from the user.
 *
 * <p>Supported specs:
 * <ul>
 *   <li>{@code id} – the Keycloak user UUID (stable, never reused)</li>
 *   <li>{@code username}, {@code email}, {@code firstName}, {@code lastName}</li>
 *   <li>{@code realm} – the realm name</li>
 *   <li>{@code attr:<name>} – any custom user attribute, e.g. {@code attr:employeeNumber}</li>
 * </ul>
 */
public final class UserFieldResolver {

    public static final String ATTR_PREFIX = "attr:";

    private UserFieldResolver() {
    }

    public static String resolve(UserModel user, RealmModel realm, String spec) {
        if (spec == null || spec.isBlank()) {
            return null;
        }
        String s = spec.trim();

        if (s.regionMatches(true, 0, ATTR_PREFIX, 0, ATTR_PREFIX.length())) {
            return user.getFirstAttribute(s.substring(ATTR_PREFIX.length()).trim());
        }

        switch (s) {
            case "id":
            case "userId":
                return user.getId();
            case "username":
                return user.getUsername();
            case "email":
                return user.getEmail();
            case "firstName":
                return user.getFirstName();
            case "lastName":
                return user.getLastName();
            case "realm":
                return realm.getName();
            default:
                throw new IllegalArgumentException("Unknown user field spec: " + spec);
        }
    }

    /** Default JSON field name to use when the config gives only a source spec. */
    public static String defaultFieldName(String spec) {
        String s = spec.trim();
        if (s.regionMatches(true, 0, ATTR_PREFIX, 0, ATTR_PREFIX.length())) {
            return s.substring(ATTR_PREFIX.length()).trim();
        }
        return "id".equals(s) ? "userId" : s;
    }
}
