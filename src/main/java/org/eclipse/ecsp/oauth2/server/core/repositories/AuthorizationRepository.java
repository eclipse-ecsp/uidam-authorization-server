/********************************************************************************
 * Copyright (c) 2023-24 Harman International 
 *
 * <p>Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at 
 *
 * <p>http://www.apache.org/licenses/LICENSE-2.0  
 *  
 * <p> Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 * <p>SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/

package org.eclipse.ecsp.oauth2.server.core.repositories;

import org.eclipse.ecsp.oauth2.server.core.entities.Authorization;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * The AuthorizationRepository interface provides methods for interacting with the Authorization entities in the
 * database.
 */
@Repository
public interface AuthorizationRepository extends JpaRepository<Authorization, String> {
    Optional<Authorization> findByState(String state);

    Optional<Authorization> findByAuthorizationCodeValue(String authorizationCode);

    Optional<Authorization> findByAccessTokenValue(String accessToken);

    Optional<Authorization> findByRefreshTokenValue(String refreshToken);

    Optional<Authorization> findByOidcIdTokenValue(String idToken);

    Optional<Authorization> findByUserCodeValue(String userCode);

    Optional<Authorization> findByDeviceCodeValue(String deviceCode);

    /**
     * This method retrieves a list of Authorization entities based on the principalName and accessTokenExpiresAt.
     * It uses a custom query to perform this operation.
     * Username comparison is case-insensitive by converting both sides to lowercase.
     *
     * @param principalName the principal name to be used in the search criteria.
     * @param accessTokenExpiresAt the access token expiry time to be used in the search criteria.
     * @return a List of matching Authorization entities.
     */
    @Query("select a from Authorization a where a.principalName = LOWER(:principalName) "
        + "AND a.accessTokenExpiresAt >= :accessTokenExpiresAt")
    List<Authorization> findByPrincipalNameAndAccessTokenExpiresAt(
        @Param("principalName") String principalName, @Param("accessTokenExpiresAt")Instant accessTokenExpiresAt);
    
    /**
     * This method retrieves active authorization sessions for a user.
     * It filters by principal name, authorization grant type, and ensures tokens are not expired.
     * This method is optimized for session management queries with proper database indexing.
     * Username comparison is case-insensitive by converting both sides to lowercase.
     *
     * @param principalName the principal name (username) to search for
     * @param grantType the authorization grant type (e.g., "authorization_code")
     * @param currentTime the current time to compare against token expiration
     * @return a List of active Authorization entities for the user
     */
    @Query("select a from Authorization a where LOWER(a.principalName) = LOWER(:principalName) "
            + "AND a.authorizationGrantType = :grantType "
            + "AND a.accessTokenExpiresAt > :currentTime")
    List<Authorization> findActiveSessionsByPrincipalNameAndGrantType(
            @Param("principalName") String principalName,
            @Param("grantType") String grantType,
            @Param("currentTime") Instant currentTime);
    
    /** 
     * This method retrieves a list of Authorization entities based on the principalName, 
     * clientId, and accessTokenExpiresAt,It uses a custom query to perform this operation.
     * Username comparison is case-insensitive by converting both sides to lowercase.
     *
     * @param principalName the principal name to be used in the search criteria.
     * @param clientId the client ID to be used in the search criteria.
     * @param accessTokenExpiresAt the access token expiry time to be used in the search criteria.
     * @return a List of matching Authorization entities.
     */
    @Query("select a from Authorization a where LOWER(a.principalName) = LOWER(:principalName) "
            + " AND a.registeredClientId = :clientId " + "AND a.accessTokenExpiresAt >= :accessTokenExpiresAt")
    List<Authorization> findByPrincipalNameClientAndAccessTokenExpiresAt(@Param("principalName") String principalName,
            @Param("clientId") String clientId, @Param("accessTokenExpiresAt") Instant accessTokenExpiresAt);    
    
    /**
     * This method retrieves a list of Authorization entities based on the principalName and clientId where either the
     * access token OR refresh token is still valid (not expired). This ensures we capture all valid authorizations for
     * logout, even if access tokens are expired but refresh tokens are still valid. NOTE: Excludes client_credentials
     * grant type tokens as they are not tied to user sessions and should not be revoked during user logout operations.
     * Username comparison is case-insensitive by converting both sides to lowercase.
     *
     * @param principalName the principal name to be used in the search criteria.
     * @param clientId the client ID to be used in the search criteria.
     * @param currentTime the current time to compare against token expiration times.
     * @return a List of matching Authorization entities with valid tokens (excluding client_credentials).
     */
    @Query("select a from Authorization a where LOWER(a.principalName) = LOWER(:principalName) "
            + " AND a.registeredClientId = :clientId " + " AND a.authorizationGrantType != 'client_credentials' "
            + " AND (a.accessTokenExpiresAt >= :currentTime OR a.refreshTokenExpiresAt >= :currentTime)")
    List<Authorization> findByPrincipalNameClientAndValidTokens(@Param("principalName") String principalName,
            @Param("clientId") String clientId, @Param("currentTime") Instant currentTime);

    /**
     * This method retrieves an Authorization entity based on the token.
     * It uses a custom query to perform this operation.
     * The token can be a state, authorization code, access token, refresh token, OIDC ID token, user code,
     * or device code.
     *
     * @param token the token to be used in the search criteria.
     * @return an Optional containing the matching Authorization entity, or an empty Optional if no match is found.
     */
    @Query("select a from Authorization a where a.state = :token"
        + " or a.authorizationCodeValue = :token"
        + " or a.accessTokenValue = :hashedToken"
        + " or a.refreshTokenValue = :hashedToken"
        + " or a.oidcIdTokenValue = :hashedToken"
        + " or a.userCodeValue = :token"
        + " or a.deviceCodeValue = :token"
    )
    Optional<Authorization> findByStateOrAuthCodeOrAccessTokenOrRefreshTokenOrOidcIdTokenOrUserCodeOrDeviceCode(
        @Param("token") String token, @Param("hashedToken") String hashedToken);
    
    /**
     * This method retrieves a list of Authorization entities based on the
     *  accessTokenExpiresAt. It uses a custom query to perform
     * this operation.
     *
     * @param tokenExpiresAt the access token expiry time to be used in the
     *                             search criteria.
     * @return a List of matching Authorization entities id.
     */
    @Query("select a.id from Authorization a where a.accessTokenExpiresAt <= :tokenExpiresAt "
            + "OR a.authorizationCodeExpiresAt <= :tokenExpiresAt "
            + "OR a.refreshTokenExpiresAt <= :tokenExpiresAt "
            + "OR a.oidcIdTokenExpiresAt <= :tokenExpiresAt "
            + "OR userCodeExpiresAt <= :tokenExpiresAt "
            + "OR a.deviceCodeExpiresAt <= :tokenExpiresAt ORDER BY a.id DESC LIMIT :limit")
    List<String> findByTokenOrCodeExpiresBefore(@Param("tokenExpiresAt") Instant tokenExpiresAt,
            @Param(value = "limit") int limit);
    
    /**
     * This method retrieves count of Authorization entities based on the
     *  accessTokenExpiresAt. It uses a custom query to perform
     * this operation.
     *
     * @param tokenExpiresAt the access token expiry time to be used in the
     *                             search criteria.
     * @return count.
     */
    @Query("select count(a) from Authorization a where a.accessTokenExpiresAt <= :tokenExpiresAt "
            + "OR a.authorizationCodeExpiresAt <= :tokenExpiresAt "
            + "OR a.refreshTokenExpiresAt <= :tokenExpiresAt "
            + "OR a.oidcIdTokenExpiresAt <= :tokenExpiresAt "
            + "OR userCodeExpiresAt <= :tokenExpiresAt "
            + "OR a.deviceCodeExpiresAt <= :tokenExpiresAt")
    long countByTokenOrCodeExpiresBefore(@Param("tokenExpiresAt") Instant tokenExpiresAt);

}

