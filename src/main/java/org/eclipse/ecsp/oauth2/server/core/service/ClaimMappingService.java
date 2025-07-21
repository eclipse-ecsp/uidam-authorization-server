package org.eclipse.ecsp.oauth2.server.core.service;

import org.apache.commons.lang3.StringUtils;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.ExternalIdpRegisteredClient;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.exception.ClaimValidationException;
import org.eclipse.ecsp.oauth2.server.core.request.dto.ClaimsToUserMapper;
import org.eclipse.ecsp.oauth2.server.core.request.dto.FederatedUserDto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import java.util.List;
import java.util.Map;

/**
 * Service responsible for mapping and validating claims from external Identity
 * Providers (IDPs). Handles claim validation conditions and mapping of IDP
 * claims to internal user representations.
 */
@Service
public class ClaimMappingService {

    private static final Logger LOGGER = LoggerFactory.getLogger(ClaimMappingService.class);

    private final TenantConfigurationService tenantConfigurationService;
    private final ClaimsToUserMapper userMapper;

    /**
     * Constructs a new ClaimMappingService.
     *
     * @param tenantConfigurationService Service for tenant configuration
     * @param userMapper                 Mapper for converting claims to user objects
     */
    public ClaimMappingService(TenantConfigurationService tenantConfigurationService, ClaimsToUserMapper userMapper) {
        if (tenantConfigurationService == null || userMapper == null) {
            throw new IllegalArgumentException("TenantConfigurationService and ClaimsToUserMapper cannot be null");
        }
        this.tenantConfigurationService = tenantConfigurationService;
        this.userMapper = userMapper;
        LOGGER.debug("ClaimMappingService initialized");
    }

    /**
     * Validates claims from an IDP against configured conditions.
     *
     * @param registrationId Registered IDP client ID
     * @param claims         Claims received from the IDP
     * @return true if conditions are met or no conditions are configured
     * @throws ClaimValidationException if a required claim is missing or validation
     *                                  fails
     */
    public boolean validateClaimCondition(String registrationId, Map<String, Object> claims) {
        LOGGER.debug("Validating claims for registrationId: {}", registrationId);

        ExternalIdpRegisteredClient idpConfig = getIdpConfigByRegistrationId(registrationId);
        
        if (idpConfig == null || idpConfig.getConditions() == null
                || StringUtils.isEmpty(idpConfig.getConditions().getClaimKey())) {
            LOGGER.debug("No conditions found for registrationId: {}. Validation passed.", registrationId);
            return true;
        }

        ExternalIdpRegisteredClient.Condition condition = idpConfig.getConditions();
        String claimKey = condition.getClaimKey();
        String expectedValue = condition.getExpectedValue();
        String operator = condition.getOperator();

        LOGGER.debug("Validating claim - key: {}, expectedValue: {}, operator: {}", claimKey, expectedValue, operator);

        validateClaimExists(claimKey, claims);

        String actualValueStr = String.valueOf(claims.get(claimKey));
        return evaluateCondition(operator, expectedValue, actualValueStr);
    }

    /**
     * Validates that a required claim exists in the claims map.
     *
     * @param claimKey The key of the claim to validate
     * @param claims   The map of claims to check
     * @throws ClaimValidationException if the claim is missing or null
     */
    private void validateClaimExists(String claimKey, Map<String, Object> claims) {
        if (!claims.containsKey(claimKey) || claims.get(claimKey) == null) {
            LOGGER.error("Required claim key missing or null: {}", claimKey);
            throw new ClaimValidationException("Required claim key missing or null: " + claimKey);
        }
    }

    /**
     * Evaluates a condition based on the specified operator and values.
     *
     * @param operator      The comparison operator to use
     * @param expectedValue The expected value to compare against
     * @param actualValue   The actual value from the claims
     * @return true if the condition is met, false otherwise
     * @throws ClaimValidationException if the operator is unsupported or the value
     *                                  format is invalid
     */
    private boolean evaluateCondition(String operator, String expectedValue, String actualValue) {
        if (operator == null || expectedValue == null || actualValue == null) {
            String errorMessage = String.format("Operator %s or expectedValue %s or actualValue %s cannot be null",
                    operator, expectedValue, actualValue);
            LOGGER.error(errorMessage);
            throw new ClaimValidationException(errorMessage);
        }

        switch (operator.toLowerCase().trim()) {
            case "equals":
                boolean result = expectedValue.trim().equals(actualValue.trim());
                LOGGER.debug("Equals operator validation result: {} (expected: {}, actual: {})", result, expectedValue,
                        actualValue);
                return result;

            case "in":
                if (!expectedValue.contains(",")) {
                    LOGGER.error("Invalid format for 'in' operator. Expected comma-separated values");
                    throw new ClaimValidationException(
                            "Invalid format for 'in' operator. Expected comma-separated values");
                }
                boolean inResult = List.of(expectedValue.split(",")).stream().map(String::trim)
                        .toList().contains(actualValue.trim());
                LOGGER.debug("In operator validation result: {} (allowed values: {}, actual: {})", inResult,
                        expectedValue, actualValue);
                return inResult;

            default:
                LOGGER.error("Unsupported operator: {}", operator);
                throw new ClaimValidationException("Unsupported operator: " + operator);
        }
    }

    /**
     * Maps IDP claims to an internal federated user representation. Creates a
     * FederatedUserDto object based on the claims and IDP configuration.
     *
     * @param registrationId        Registered IDP client ID
     * @param claims                Claims received from the IDP
     * @param userNameAttributeName The claim key that contains the username
     * @return FederatedUserDto containing mapped user information, or null if IDP
     *         config not found
     */
    public FederatedUserDto mapClaimsToUserRequest(String registrationId, Map<String, Object> claims,
            String userNameAttributeName) {
        LOGGER.debug("Mapping claims to user request for registrationId: {}", registrationId);

        ExternalIdpRegisteredClient idpConfig = getIdpConfigByRegistrationId(registrationId);
        if (idpConfig == null) {
            LOGGER.warn("No IDP configuration found for registrationId: {}", registrationId);
            return null;
        }

        FederatedUserDto userDto = userMapper.mapClaimsToUserRequest(claims, idpConfig);
        if (claims.containsKey(userNameAttributeName)) {
            userDto.setUserName(String.valueOf(claims.get(userNameAttributeName)));
        }

        // Set audience and default roles
        TenantProperties tenantProperties = tenantConfigurationService.getTenantProperties();
        userDto.setAud(tenantProperties.getExternalIdpClientName());
        userDto.setRoles(idpConfig.getDefaultUserRoles());
        if (StringUtils.isEmpty(userDto.getEmail())) {
            userDto.setEmail("dummy@" + idpConfig.getRegistrationId() + ".com");
        }

        LOGGER.debug("Setting default roles for user: {}", idpConfig.getDefaultUserRoles());
        LOGGER.info("Successfully mapped claims to user for registrationId: {}, username: {}, roles: {}",
                registrationId, userDto.getUserName(), userDto.getRoles());

        return userDto;
    }

    /**
     * Retrieves the IDP configuration for a given registration ID.
     *
     * @param registrationId The registration ID of the IDP
     * @return The corresponding ExternalIdpRegisteredClient configuration, or null
     *         if not found
     */
    private ExternalIdpRegisteredClient getIdpConfigByRegistrationId(String registrationId) {
        LOGGER.debug("Looking up IDP configuration for registrationId: {}", registrationId);

        TenantProperties tenantProperties = tenantConfigurationService.getTenantProperties();
        return tenantProperties.getExternalIdpRegisteredClientList().stream()
                .filter(client -> client.getRegistrationId().equals(registrationId)).findFirst().orElse(null);
    }

}
