package com.example.keycloak.numberverification;

import java.util.List;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * Turns a configuration "source spec" into a concrete value taken from the user.
 *
 * <p>Supported specs:
 *
 * <ul>
 *   <li>{@code id} – the Keycloak user UUID (stable, never reused); {@code userId} is an alias
 *   <li>{@code username}, {@code email}, {@code firstName}, {@code lastName}
 *   <li>{@code realm} – the realm name
 *   <li>{@code attr:<name>} – any custom user attribute, e.g. {@code attr:employeeNumber}
 * </ul>
 */
public final class UserFieldResolver {

    public static final String ATTR_PREFIX = "attr:";

    private static final List<String> BUILT_IN =
            List.of("id", "userId", "username", "email", "firstName", "lastName", "realm");

    private UserFieldResolver() {}

    /**
     * Checks a spec without needing a user, so both startup defaults and console input go through
     * the same rules.
     *
     * @return the trimmed spec
     * @throws IllegalArgumentException with an admin-readable message if the spec is unsupported
     */
    public static String validate(String spec) {
        if (spec == null || spec.isBlank()) {
            throw new IllegalArgumentException("source must not be blank");
        }
        String s = spec.trim();
        if (isAttribute(s)) {
            if (attributeName(s).isEmpty()) {
                throw new IllegalArgumentException("'attr:' needs an attribute name");
            }
            return s;
        }
        if (!BUILT_IN.contains(s)) {
            throw new IllegalArgumentException(
                    "unknown source '"
                            + s
                            + "'. Use id, username, email, firstName, lastName, realm or"
                            + " attr:<name>");
        }
        return s;
    }

    /**
     * @return the user's value for the spec, or {@code null} if the spec is blank or the user has
     *     no such value
     * @throws IllegalArgumentException if the spec is unsupported
     */
    public static String resolve(UserModel user, RealmModel realm, String spec) {
        if (spec == null || spec.isBlank()) {
            return null;
        }
        String s = validate(spec);
        if (isAttribute(s)) {
            return user.getFirstAttribute(attributeName(s));
        }
        return switch (s) {
            case "id", "userId" -> user.getId();
            case "username" -> user.getUsername();
            case "email" -> user.getEmail();
            case "firstName" -> user.getFirstName();
            case "lastName" -> user.getLastName();
            case "realm" -> realm.getName();
            default -> throw new IllegalArgumentException("Unknown user field spec: " + spec);
        };
    }

    /** Default JSON field name to use when the config gives only a source spec. */
    public static String defaultFieldName(String spec) {
        String s = spec.trim();
        if (isAttribute(s)) {
            return attributeName(s);
        }
        return "id".equals(s) ? "userId" : s;
    }

    private static boolean isAttribute(String s) {
        return s.regionMatches(true, 0, ATTR_PREFIX, 0, ATTR_PREFIX.length());
    }

    private static String attributeName(String s) {
        return s.substring(ATTR_PREFIX.length()).trim();
    }
}
