package org.eclipse.ecsp.oauth2.server.core.request.dto;

import lombok.Getter;
import lombok.NonNull;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.ExternalIdpRegisteredClient;
import org.eclipse.ecsp.oauth2.server.core.request.transformer.DefaultIdpTransformer;
import org.eclipse.ecsp.oauth2.server.core.request.transformer.GoogleIdpTransformer;
import org.eclipse.ecsp.oauth2.server.core.request.transformer.IdpTransformer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.BiConsumer;

/**
 * Maps OAuth2/OIDC claims from external Identity Providers (IDPs) to internal
 * user representations. This component handles the transformation of user
 * attributes from various IDPs into a standardized {@link FederatedUserDto}
 * format.
 */
@Component
public class ClaimsToUserMapper {

    private static final Logger LOGGER = LoggerFactory.getLogger(ClaimsToUserMapper.class);

    /**
     * Enumeration of supported user fields with their corresponding names and
     * types. Each field represents a mappable attribute from external IDP claims to
     * internal user representation.
     */
    @Getter
    public enum UserField {
        USERNAME("userName", String.class), EMAIL("email", String.class), AUD("aud", String.class),
        FIRSTNAME("firstName", String.class), LASTNAME("lastName", String.class), COUNTRY("country", String.class),
        STATE("state", String.class), CITY("city", String.class), ADDRESS1("address1", String.class),
        ADDRESS2("address2", String.class), POSTALCODE("postalCode", String.class),
        PHONENUMBER("phoneNumber", String.class), GENDER("gender", String.class);

        private final String fieldName;
        private final Class<?> fieldType;

        UserField(String fieldName, Class<?> fieldType) {
            this.fieldName = fieldName;
            this.fieldType = fieldType;
        }

        /**
         * Resolves a claimMappings key to a known {@link UserField}, case-insensitively, without
         * throwing when there is no match. Callers use an empty result to decide the value should
         * be routed to {@link BaseUserDto#getAdditionalAttributes()} as a dynamic attribute
         * instead of a fixed field.
         *
         * @param fieldName the claimMappings target-field key
         * @return the matching {@link UserField}, or empty if none of the fixed fields match
         */
        public static Optional<UserField> tryParse(String fieldName) {
            for (UserField field : values()) {
                if (field.name().equalsIgnoreCase(fieldName)) {
                    return Optional.of(field);
                }
            }
            return Optional.empty();
        }
    }

    /**
     * Map of field setters that define how each UserField should be set on the
     * FederatedUserDto. Uses BiConsumer to provide type-safe setting of values.
     */
    private static final EnumMap<UserField, BiConsumer<FederatedUserDto, Object>> FIELD_SETTERS = new EnumMap<>(
            UserField.class);

    static {
        FIELD_SETTERS.put(UserField.USERNAME, (dto, value) -> dto.setUserName((String) value));
        FIELD_SETTERS.put(UserField.EMAIL, (dto, value) -> dto.setEmail((String) value));
        FIELD_SETTERS.put(UserField.AUD, (dto, value) -> dto.setAud((String) value));
        FIELD_SETTERS.put(UserField.FIRSTNAME, (dto, value) -> dto.setFirstName((String) value));
        FIELD_SETTERS.put(UserField.LASTNAME, (dto, value) -> dto.setLastName((String) value));
        FIELD_SETTERS.put(UserField.COUNTRY, (dto, value) -> dto.setCountry((String) value));
        FIELD_SETTERS.put(UserField.STATE, (dto, value) -> dto.setState((String) value));
        FIELD_SETTERS.put(UserField.CITY, (dto, value) -> dto.setCity((String) value));
        FIELD_SETTERS.put(UserField.ADDRESS1, (dto, value) -> dto.setAddress1((String) value));
        FIELD_SETTERS.put(UserField.ADDRESS2, (dto, value) -> dto.setAddress2((String) value));
        FIELD_SETTERS.put(UserField.POSTALCODE, (dto, value) -> dto.setPostalCode((String) value));
        FIELD_SETTERS.put(UserField.PHONENUMBER, (dto, value) -> dto.setPhoneNumber((String) value));
        FIELD_SETTERS.put(UserField.GENDER, (dto, value) -> dto.setGender((String) value));
    }

    /**
     * Map of IDP-specific transformers keyed by IDP registration ID. Each
     * transformer handles the specific transformation logic for its IDP.
     */
    private Map<String, IdpTransformer> transformers = new HashMap<>();

    /**
     * Default transformer used when no IDP-specific transformer is found. Provides
     * fallback transformation logic for unknown IDPs.
     */
    private DefaultIdpTransformer defaultTransformer;

    public ClaimsToUserMapper() {
        this.defaultTransformer = new DefaultIdpTransformer();
        this.transformers = Map.of("google", new GoogleIdpTransformer());
    }

    /**
     * Maps claims from an external IDP to a {@link FederatedUserDto} object.
     *
     * @param claims    The raw claims received from the identity provider
     * @param idpConfig The configuration for the external IDP
     * @return A populated {@link FederatedUserDto} containing the transformed user
     *         information
     * @throws NullPointerException if either claims or idpConfig is null
     */
    public FederatedUserDto mapClaimsToUserRequest(@NonNull Map<String, Object> claims,
            @NonNull ExternalIdpRegisteredClient idpConfig) {
        LOGGER.info("Processing user claims from identity provider: {}", idpConfig.getRegistrationId());
        LOGGER.debug("Mapping claims to user request for IDP: {}", idpConfig.getRegistrationId());

        FederatedUserDto userDto = new FederatedUserDto();
        userDto.setIdentityProviderName(idpConfig.getRegistrationId());
        userDto.setStatus("ACTIVE");

        IdpTransformer transformer = transformers.getOrDefault(idpConfig.getRegistrationId(), defaultTransformer);
        LOGGER.debug("Using transformer: {}", transformer.getClass().getSimpleName());

        Optional.ofNullable(idpConfig.getMappings())
                .ifPresent(mappings -> applyMappings(claims, mappings, userDto, transformer));

        LOGGER.info("Successfully mapped claims to user: {}", userDto.getUserName());
        LOGGER.debug("Completed mapping claims to user request: {}", userDto);
        return userDto;
    }

    /**
     * Applies the configured mappings to transform IDP claims into user fields.
     *
     * @param claims      The raw claims from the IDP
     * @param mappings    The configured field mappings
     * @param userDto     The target user DTO
     * @param transformer The IDP-specific transformer to use
     * @throws NullPointerException if any parameter is null
     */
    private void applyMappings(@NonNull Map<String, Object> claims, @NonNull Map<String, String> mappings,
            @NonNull FederatedUserDto userDto, @NonNull IdpTransformer transformer) {
        LOGGER.debug("Applying {} field mappings", mappings.size());

        mappings.forEach((dtoField, claimKey) -> {
            Object claimValue = claims.get(claimKey);
            if (claimValue != null) {
                LOGGER.trace("Mapping field {} with claim key {}", dtoField, claimKey);
                setFieldValue(userDto, dtoField, claimValue, transformer);
            } else {
                LOGGER.debug("Skipping null claim value for key: {}", claimKey);
            }
        });
    }

    /**
     * Sets a specific field value on the user DTO after applying appropriate
     * transformations. If {@code fieldName} does not match one of the fixed
     * {@link UserField} values, it is treated as a dynamic attribute and stored in
     * {@link BaseUserDto#getAdditionalAttributes()} instead, to be persisted downstream as a
     * user_attribute_values entry by user-management.
     *
     * @param userDto     The target user DTO
     * @param fieldName   The name of the field to set
     * @param value       The value to set
     * @param transformer The transformer to apply to the value
     * @throws IllegalStateException if the field value cannot be set
     * @throws NullPointerException  if any parameter is null
     */
    private void setFieldValue(@NonNull FederatedUserDto userDto, @NonNull String fieldName, @NonNull Object value,
            @NonNull IdpTransformer transformer) {
        Optional<UserField> userFieldOpt = UserField.tryParse(fieldName);
        if (userFieldOpt.isEmpty()) {
            LOGGER.debug("'{}' is not a known user field; storing as dynamic attribute", fieldName);
            userDto.getAdditionalAttributes().put(fieldName, value);
            return;
        }
        UserField userField = userFieldOpt.get();
        try {
            BiConsumer<FederatedUserDto, Object> setter = FIELD_SETTERS.get(userField);
            Object transformedValue = transformField(transformer, userField, value);
            setter.accept(userDto, transformedValue);
            LOGGER.trace("Successfully set field {} with transformed value", fieldName);
        } catch (Exception e) {
            LOGGER.error("Error setting field {} for user transformation: {}", fieldName, e.getMessage(), e);
            throw new IllegalStateException(
                    String.format("Failed to set field '%s' during claims transformation", fieldName), e);
        }
    }

    /**
     * Transforms a field value using the appropriate transformer method based on
     * the field type.
     *
     * @param transformer The transformer to use
     * @param field       The field being transformed
     * @param value       The value to transform
     * @return The transformed value
     * @throws NullPointerException if any parameter is null
     */
    private Object transformField(@NonNull IdpTransformer transformer, @NonNull UserField field,
            @NonNull Object value) {
        return switch (field) {
            case USERNAME -> transformer.transformUserName(value);
            case EMAIL -> transformer.transformEmail(value);
            case AUD -> transformer.transformAud(value);
            case FIRSTNAME -> transformer.transformFirstName(value);
            case LASTNAME -> transformer.transformLastName(value);
            case COUNTRY -> transformer.transformCountry(value);
            case STATE -> transformer.transformState(value);
            case CITY -> transformer.transformCity(value);
            case ADDRESS1 -> transformer.transformAddress1(value);
            case ADDRESS2 -> transformer.transformAddress2(value);
            case POSTALCODE -> transformer.transformPostalCode(value);
            case PHONENUMBER -> transformer.transformPhoneNumber(value);
            case GENDER -> transformer.transformGender(value);
        };
    }
}
