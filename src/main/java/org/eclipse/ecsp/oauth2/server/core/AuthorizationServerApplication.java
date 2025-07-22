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

package org.eclipse.ecsp.oauth2.server.core;

import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.MultiTenantProperties;
import org.eclipse.ecsp.oauth2.server.core.interceptor.CorrelationIdInterceptor;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.retry.annotation.EnableRetry;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * The AuthorizationServerApplication is the main class for the microservice.
 */
@ComponentScan(basePackages = {"org.eclipse.ecsp"})
@EnableConfigurationProperties(MultiTenantProperties.class)
@EnableScheduling
@EnableRetry
@SpringBootApplication(scanBasePackages = {"org.eclipse.ecsp"})
public class AuthorizationServerApplication {

    protected AuthorizationServerApplication() {
        // Prevent instantiation
    }

    /**
     * The main method, which is the entry point for the Spring application.
     *
     * @param args Array of strings representing command line arguments.
     */
    public static void main(String[] args) {
        SpringApplication.run(AuthorizationServerApplication.class, args);
    }

    /**
    /**
     * This method creates an instance of WebMvcConfigurer.
     * The WebMvcConfigurer interface has methods for customizing the Java-based configurations for Spring MVC.
     * In this method, an anonymous class is created that overrides the addInterceptors method to add
     * CorrelationIdInterceptor. Tenant resolution is handled by TenantResolutionFilter at the filter level.
     *
     * @return a WebMvcConfigurer that adds the correlation ID interceptor to the InterceptorRegistry.
     */
    @Bean
    public WebMvcConfigurer adapter() {
        return new WebMvcConfigurer() {
            @Override
            public void addInterceptors(InterceptorRegistry registry) {
                // Add CorrelationIdInterceptor for request tracing
                registry.addInterceptor(new CorrelationIdInterceptor());
            }

        };
    }
}
