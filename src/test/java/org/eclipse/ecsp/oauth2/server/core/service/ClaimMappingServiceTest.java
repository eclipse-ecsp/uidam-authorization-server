package org.eclipse.ecsp.oauth2.server.core.service;

import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.ExternalIdpRegisteredClient;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.exception.ClaimValidationException;
import org.eclipse.ecsp.oauth2.server.core.request.dto.ClaimsToUserMapper;
import org.eclipse.ecsp.oauth2.server.core.request.dto.FederatedUserDto;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

@ExtendWith(MockitoExtension.class)
class ClaimMappingServiceTest {

    @Mock
    private TenantConfigurationService tenantConfigurationService;

    @Mock
    private TenantProperties tenantProperties;

    @Mock
    private ClaimsToUserMapper userMapper;

    private ClaimMappingService claimMappingService;
    private ExternalIdpRegisteredClient idpConfig;
    private static final String REGISTRATION_ID = "test-idp";

    @BeforeEach
    void setUp() {
        claimMappingService = new ClaimMappingService(tenantConfigurationService, userMapper);

        // Setup IDP config
        idpConfig = new ExternalIdpRegisteredClient();
        idpConfig.setRegistrationId(REGISTRATION_ID);
        Set<String> defaultRoles = Set.of("USER", "GUEST");
        idpConfig.setDefaultUserRoles(defaultRoles);

        // Mock tenant configuration service - using lenient to avoid unnecessary stubbing exceptions
        Mockito.lenient().when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
    }

    @Test
    void constructor_ShouldThrowException_WhenNullParameters() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> new ClaimMappingService(null, userMapper));
        Assertions.assertThrows(IllegalArgumentException.class, 
                () -> new ClaimMappingService(tenantConfigurationService, null));
    }

    @Test
    void validateClaimCondition_ShouldReturnTrue_WhenNoConditionsConfigured() {
        // Given
        Mockito.when(tenantProperties.getExternalIdpRegisteredClientList()).thenReturn(List.of(idpConfig));

        // When
        boolean result = claimMappingService.validateClaimCondition(REGISTRATION_ID, Collections.emptyMap());

        // Then
        Assertions.assertTrue(result);
    }

    @Test
    void validateClaimCondition_ShouldReturnTrue_WhenNoMatchingIdpConfig() {
        // Given
        Mockito.when(tenantProperties.getExternalIdpRegisteredClientList()).thenReturn(Collections.emptyList());

        // When
        boolean result = claimMappingService.validateClaimCondition(REGISTRATION_ID, Collections.emptyMap());

        // Then
        Assertions.assertTrue(result);
    }

    @Test
    void validateClaimCondition_ShouldThrowException_WhenRequiredClaimMissing() {
        // Given
        setupCondition("department", "IT", "equals");
        Mockito.when(tenantProperties.getExternalIdpRegisteredClientList()).thenReturn(List.of(idpConfig));

        // When & Then
        Assertions.assertThrows(ClaimValidationException.class,
                () -> claimMappingService.validateClaimCondition(REGISTRATION_ID, Collections.emptyMap()));
    }

    @Test
    void validateClaimCondition_ShouldThrowException_WhenClaimValueNull() {
        // Given
        setupCondition("department", "IT", "equals");
        Mockito.when(tenantProperties.getExternalIdpRegisteredClientList()).thenReturn(List.of(idpConfig));

        Map<String, Object> claims = new HashMap<>();
        claims.put("department", null);

        // When & Then
        Assertions.assertThrows(ClaimValidationException.class,
                () -> claimMappingService.validateClaimCondition(REGISTRATION_ID, claims));
    }

    @Test
    void validateClaimCondition_ShouldReturnTrue_WhenEqualsOperatorMatches() {
        // Given
        setupCondition("department", "IT", "equals");
        Mockito.when(tenantProperties.getExternalIdpRegisteredClientList()).thenReturn(List.of(idpConfig));

        Map<String, Object> claims = new HashMap<>();
        claims.put("department", "IT");

        // When
        boolean result = claimMappingService.validateClaimCondition(REGISTRATION_ID, claims);

        // Then
        Assertions.assertTrue(result);
    }

    @Test
    void validateClaimCondition_ShouldReturnFalse_WhenEqualsOperatorDoesNotMatch() {
        // Given
        setupCondition("department", "IT", "equals");
        Mockito.when(tenantProperties.getExternalIdpRegisteredClientList()).thenReturn(List.of(idpConfig));

        Map<String, Object> claims = new HashMap<>();
        claims.put("department", "HR");

        // When
        boolean result = claimMappingService.validateClaimCondition(REGISTRATION_ID, claims);

        // Then
        Assertions.assertFalse(result);
    }

    @Test
    void validateClaimCondition_ShouldReturnTrue_WhenInOperatorMatches() {
        // Given
        setupCondition("role", "admin,user,guest", "in");
        Mockito.when(tenantProperties.getExternalIdpRegisteredClientList()).thenReturn(List.of(idpConfig));

        Map<String, Object> claims = new HashMap<>();
        claims.put("role", "admin");

        // When
        boolean result = claimMappingService.validateClaimCondition(REGISTRATION_ID, claims);

        // Then
        Assertions.assertTrue(result);
    }

    @Test
    void validateClaimCondition_ShouldThrowException_WhenInOperatorInvalidFormat() {
        // Given
        setupCondition("role", "single_value", "in");
        Mockito.when(tenantProperties.getExternalIdpRegisteredClientList()).thenReturn(List.of(idpConfig));

        Map<String, Object> claims = new HashMap<>();
        claims.put("role", "admin");

        // When & Then
        Assertions.assertThrows(ClaimValidationException.class,
                () -> claimMappingService.validateClaimCondition(REGISTRATION_ID, claims));
    }

    @Test
    void validateClaimCondition_ShouldThrowException_WhenUnsupportedOperator() {
        // Given
        setupCondition("age", "18", "greater_than");
        Mockito.when(tenantProperties.getExternalIdpRegisteredClientList()).thenReturn(List.of(idpConfig));

        Map<String, Object> claims = new HashMap<>();
        claims.put("age", "20");

        // When & Then
        Assertions.assertThrows(ClaimValidationException.class,
                () -> claimMappingService.validateClaimCondition(REGISTRATION_ID, claims));
    }

    @Test
    void mapClaimsToUserRequest_ShouldReturnNull_WhenNoIdpConfigFound() {
        // Given
        Mockito.when(tenantProperties.getExternalIdpRegisteredClientList()).thenReturn(Collections.emptyList());

        // When
        FederatedUserDto result = claimMappingService.mapClaimsToUserRequest(REGISTRATION_ID, Collections.emptyMap(),
                "email");

        // Then
        Assertions.assertNull(result);
    }

    @Test
    void mapClaimsToUserRequest_ShouldMapSuccessfully_WithAllFields() {
        // Given
        String userNameAttribute = "email";
        Map<String, Object> claims = new HashMap<>();
        claims.put(userNameAttribute, "test@example.com");

        Mockito.when(tenantProperties.getExternalIdpRegisteredClientList()).thenReturn(List.of(idpConfig));
        Mockito.when(tenantProperties.getExternalIdpClientName()).thenReturn("test-client");

        FederatedUserDto expectedUser = new FederatedUserDto();
        Mockito.when(userMapper.mapClaimsToUserRequest(claims, idpConfig)).thenReturn(expectedUser);

        // When
        FederatedUserDto result = claimMappingService.mapClaimsToUserRequest(REGISTRATION_ID, claims,
                userNameAttribute);

        // Then
        Assertions.assertNotNull(result);
        Assertions.assertEquals("test@example.com", result.getUserName());
        Assertions.assertEquals("test-client", result.getAud());
        Assertions.assertEquals(idpConfig.getDefaultUserRoles(), result.getRoles());
        Mockito.verify(userMapper).mapClaimsToUserRequest(claims, idpConfig);
    }

    @Test
    void mapClaimsToUserRequest_ShouldMapSuccessfully_WithoutConditions() {
        // Given
        String userNameAttribute = "email";
        Map<String, Object> claims = new HashMap<>();
        claims.put(userNameAttribute, "test@example.com");
        claims.put("firstName", "John");
        claims.put("lastName", "Doe");

        Mockito.when(tenantProperties.getExternalIdpRegisteredClientList()).thenReturn(List.of(idpConfig));
        Mockito.when(tenantProperties.getExternalIdpClientName()).thenReturn("test-client");

        FederatedUserDto expectedUser = new FederatedUserDto();
        expectedUser.setUserName("test@example.com");
        expectedUser.setFirstName("John");
        expectedUser.setLastName("Doe");
        Mockito.when(userMapper.mapClaimsToUserRequest(claims, idpConfig)).thenReturn(expectedUser);

        // When
        FederatedUserDto result = claimMappingService.mapClaimsToUserRequest(REGISTRATION_ID, claims,
                userNameAttribute);

        // Then
        Assertions.assertNotNull(result);
        Assertions.assertEquals("test@example.com", result.getUserName());
        Assertions.assertEquals("John", result.getFirstName());
        Assertions.assertEquals("Doe", result.getLastName());
        Assertions.assertEquals("test-client", result.getAud());
        Assertions.assertEquals(idpConfig.getDefaultUserRoles(), result.getRoles());
        Mockito.verify(userMapper).mapClaimsToUserRequest(claims, idpConfig);
    }

    private void setupCondition(String claimKey, String expectedValue, String operator) {
        ExternalIdpRegisteredClient.Condition condition = new ExternalIdpRegisteredClient.Condition();
        condition.setClaimKey(claimKey);
        condition.setExpectedValue(expectedValue);
        condition.setOperator(operator);
        idpConfig.setConditions(condition);
    }
}