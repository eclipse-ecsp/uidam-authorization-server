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

package org.eclipse.ecsp.oauth2.server.core.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.env.Environment;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.jdbc.datasource.lookup.AbstractRoutingDataSource;
import org.springframework.util.StringUtils;
import javax.sql.DataSource;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

/**
 * Multiple Datasource configuration for the tenants.
 */ 
//@Configuration
public class MultitenantConfiguration {

    private static final String TENANT_DEFAULT = "${tenant.default}";
    private static final String TENANT_IDS = "${tenant.ids}";
    private static final String TENANT_PROPERTIES_PREFIX = "tenant.tenants.%s.%s";
    private static final String TENANT_PROPERTIES_FILE = "classpath:tenant-%s.properties";
    private static final String ENV_KEY_FORMAT = "%s";
    private static final String POSTGRES_DRIVER_CLASS_NAME = "postgres.driver.class.name";
    private static final String POSTGRES_USERNAME = "postgres.username";
    private static final String POSTGRES_PASSWORD = "postgres.password";
    private static final String POSTGRES_JDBC_URL = "postgres.jdbc.url";
    private static final String ERROR_LOADING_TENANT_FILE = "Error loading tenant properties file for %s: %s";
    private static final String MISSING_DB_PROPS = "Missing required database properties for tenant: %s";
    private static final String CONFIGURE_TENANT_ERROR = "Problem configuring tenant datasource for %s: %s";
    private static final String NO_TENANT_DATASOURCES = "No tenant datasources could be configured";

    @Value(TENANT_DEFAULT)
    private String defaultTenant;
    
    @Autowired
    private Environment env;
    
    @Autowired
    private ResourceLoader resourceLoader;
    
    @Value("#{'" + TENANT_IDS + "'.split(',')}")
    private List<String> tenantIds;

    private final Map<String, Properties> tenantPropertiesCache = new HashMap<>();

    private String resolveProperty(String tenantId, String propertyKey) {
        String fullKey = String.format(TENANT_PROPERTIES_PREFIX, tenantId, propertyKey);
        String value = env.getProperty(fullKey);
        
        if (!StringUtils.hasText(value)) {
            // Try to get from tenant properties file (cached)
            try {
                Properties props = tenantPropertiesCache.get(tenantId);
                if (props == null) {
                    Resource resource = resourceLoader.getResource(String.format(TENANT_PROPERTIES_FILE, tenantId));
                    if (resource.exists()) {
                        props = new Properties();
                        try (InputStream is = resource.getInputStream()) {
                            props.load(is);
                        }
                        tenantPropertiesCache.put(tenantId, props);
                    }
                }
                if (props != null) {
                    value = props.getProperty(fullKey);
                }
            } catch (IOException e) {
                // Log the error but continue - we'll try other sources
                System.err.println(String.format(ERROR_LOADING_TENANT_FILE, tenantId, e.getMessage()));
            }
        }
        
        // If still not found, try Kubernetes config map format (ENV)
        if (!StringUtils.hasText(value)) {
            String envKey = fullKey.replace('.', '_').toUpperCase();
            value = env.getProperty(String.format(ENV_KEY_FORMAT, envKey));
        }
        
        return value;
    }

    /**
     * Creating datasource for all the tenants based on the tenants configured DB details
     * It runover all tenants and create Datasource and add to AbstractRoutingDataSource.
     *
     * @return DataSource
     */
    @Bean
    @Primary
    @ConfigurationProperties(prefix = "tenant-")
    public DataSource dataSource() {
        Map<Object, Object> resolvedDataSources = new HashMap<>();

        for (String tenantId : tenantIds) {
            DataSourceBuilder<?> dataSourceBuilder = DataSourceBuilder.create();

            try {
                String driverClassName = resolveProperty(tenantId, POSTGRES_DRIVER_CLASS_NAME);
                String username = resolveProperty(tenantId, POSTGRES_USERNAME);
                String password = resolveProperty(tenantId, POSTGRES_PASSWORD);
                String url = resolveProperty(tenantId, POSTGRES_JDBC_URL);

                if (!StringUtils.hasText(driverClassName) || !StringUtils.hasText(username) 
                    || !StringUtils.hasText(password) || !StringUtils.hasText(url)) {
                    throw new IllegalArgumentException(String.format(MISSING_DB_PROPS, tenantId));
                }

                dataSourceBuilder.driverClassName(driverClassName);
                dataSourceBuilder.username(username);
                dataSourceBuilder.password(password);
                dataSourceBuilder.url(url);
                
                resolvedDataSources.put(tenantId, dataSourceBuilder.build());
            } catch (Exception exp) {
                throw new IllegalStateException(String.format(CONFIGURE_TENANT_ERROR, tenantId, exp.getMessage()), exp);
            }
        }

        if (resolvedDataSources.isEmpty()) {
            throw new IllegalStateException(NO_TENANT_DATASOURCES);
        }

        AbstractRoutingDataSource dataSource = new MultitenantDataSource();
        dataSource.setDefaultTargetDataSource(resolvedDataSources.get(defaultTenant));
        dataSource.setTargetDataSources(resolvedDataSources);

        dataSource.afterPropertiesSet();
        return dataSource;
    }
}
