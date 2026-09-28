/*
 * Copyright (c) 2023 - 2026 Harman International
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.ecsp.utils.logger;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.PatternLayout;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.ThrowableProxy;
import ch.qos.logback.core.read.ListAppender;
import org.eclipse.ecsp.entities.IgniteEvent;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Regression coverage for the ECSP logger override and its Logback integration.
 */
class IgniteLoggerImplTest {

    private static final String HEADER = "Timestamp:0 , RequestId:request-1 , MessageId:message-1"
            + " , BizTransactionId:transaction-1 , VehicleID:vehicle-1 , EventID:event-1"
            + " , Version:null , SourceDeviceID:device-1";

    private LoggerContext context;
    private Logger delegate;
    private ListAppender<ILoggingEvent> appender;
    private IgniteLoggerImpl logger;
    private IgniteEvent event;
    private final RuntimeException failure = new IllegalStateException("logging failure");

    @BeforeEach
    void setUp() {
        context = new LoggerContext();
        delegate = context.getLogger(getClass());
        delegate.setLevel(Level.TRACE);
        delegate.setAdditive(false);
        appender = new ListAppender<>();
        appender.setContext(context);
        appender.start();
        delegate.addAppender(appender);
        logger = assertInstanceOf(IgniteLoggerImpl.class, IgniteLoggerFactory.getLogger(getClass()));
        logger.setLogger(delegate);
        event = mock(IgniteEvent.class);
        when(event.getRequestId()).thenReturn("request-1");
        when(event.getMessageId()).thenReturn("message-1");
        when(event.getBizTransactionId()).thenReturn("transaction-1");
        when(event.getVehicleId()).thenReturn("vehicle-1");
        when(event.getEventId()).thenReturn("event-1");
        when(event.getSourceDeviceId()).thenReturn("device-1");
    }

    @AfterEach
    void tearDown() {
        if (logger != null) {
            logger.getIgniteLoggersMap().remove(getClass().getName());
            logger.getIgniteLoggersMap().remove(OtherLoggerOwner.class.getName());
        }
        appender.stop();
        context.stop();
    }

    @Test
    void factoryCachesInstancesPerClass() {
        assertSame(logger, IgniteLoggerFactory.getLogger(getClass()));
        assertSame(logger, IgniteLoggerImpl.getIgniteLoggerImplInstance(getClass()));
        IgniteLogger other = IgniteLoggerFactory.getLogger(OtherLoggerOwner.class);
        assertNotSame(logger, other);
        assertSame(other, IgniteLoggerFactory.getLogger(OtherLoggerOwner.class));
    }

    @Test
    void registersConvertersUsingLogbackSupplierApi() {
        assertInstanceOf(IgniteCallerDataConverter.class,
                PatternLayout.DEFAULT_CONVERTER_SUPPLIER_MAP.get("caller").get());
        for (String keyword : List.of("ex", "exception", "throwable")) {
            assertInstanceOf(IgniteThrowableProxyConverter.class,
                    PatternLayout.DEFAULT_CONVERTER_SUPPLIER_MAP.get(keyword).get());
        }
    }

    @ParameterizedTest(name = "{0}, event={1}, overload={2}")
    @MethodSource("loggingCases")
    void preservesLevelMessageArgumentsAndThrowable(String level, boolean withEvent, Overload overload)
            throws ReflectiveOperationException {
        log(level, withEvent ? event : null, overload);

        assertEquals(1, appender.list.size());
        ILoggingEvent logged = appender.list.getFirst();
        assertEquals(Level.toLevel(level.toUpperCase(Locale.ROOT)), logged.getLevel());
        String prefix = withEvent ? HEADER + " ,message:" : "";
        assertEquals(prefix + "message value", logged.getFormattedMessage());
        if (overload == Overload.THROWABLE) {
            ThrowableProxy proxy = assertInstanceOf(ThrowableProxy.class, logged.getThrowableProxy());
            assertSame(failure, proxy.getThrowable());
        } else {
            assertNull(logged.getThrowableProxy());
        }
    }

    @ParameterizedTest(name = "disabled {0}, event={1}, overload={2}")
    @MethodSource("loggingCases")
    void disabledLevelsDoNotEmitMessages(String level, boolean withEvent, Overload overload)
            throws ReflectiveOperationException {
        delegate.setLevel(Level.OFF);
        IgniteEvent unreadEvent = mock(IgniteEvent.class);

        log(level, withEvent ? unreadEvent : null, overload);

        assertTrue(appender.list.isEmpty());
        if (List.of("trace", "debug", "info").contains(level)) {
            verifyNoInteractions(unreadEvent);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"Trace", "Debug", "Info", "Warn", "Error"})
    void enabledChecksFollowDelegateLevel(String level) throws ReflectiveOperationException {
        assertEquals(true, IgniteLogger.class.getMethod("is" + level + "Enabled").invoke(logger));
        delegate.setLevel(Level.OFF);
        assertEquals(false, IgniteLogger.class.getMethod("is" + level + "Enabled").invoke(logger));
    }

    @Test
    void includesCorrelationIdWhenPresent() {
        when(event.getCorrelationId()).thenReturn("correlation-1");

        logger.info(event, "message value");

        // Preserve the existing ECSP header format, including Optional's representation.
        assertEquals(HEADER + " , CorrelationId:Optional[correlation-1] ,message:message value",
                appender.list.getFirst().getFormattedMessage());
    }

    @Test
    void omitsCorrelationIdWhenAbsent() {
        logger.info(event, "message value");

        assertEquals(HEADER + " ,message:message value", appender.list.getFirst().getFormattedMessage());
        assertFalse(appender.list.getFirst().getFormattedMessage().contains("CorrelationId"));
    }

    static Stream<Arguments> loggingCases() {
        return Stream.of("trace", "debug", "info", "warn", "error")
                .flatMap(level -> Stream.of(false, true)
                        .flatMap(withEvent -> Arrays.stream(Overload.values())
                                .map(overload -> Arguments.of(level, withEvent, overload))));
    }

    private void log(String level, IgniteEvent logEvent, Overload overload) throws ReflectiveOperationException {
        // Exercise every public overload against the same observable logging contract.
        List<Class<?>> signature = new ArrayList<>();
        List<Object> arguments = new ArrayList<>();
        if (logEvent != null) {
            signature.add(IgniteEvent.class);
            arguments.add(logEvent);
        }
        signature.add(String.class);
        arguments.add(overload == Overload.ARGUMENTS ? "message {}" : "message value");
        if (overload == Overload.ARGUMENTS) {
            signature.add(Object[].class);
            arguments.add(new Object[]{"value"});
        } else if (overload == Overload.THROWABLE) {
            signature.add(Throwable.class);
            arguments.add(failure);
        }
        IgniteLogger.class.getMethod(level, signature.toArray(Class<?>[]::new))
                .invoke(logger, arguments.toArray());
    }

    private enum Overload {
        MESSAGE, ARGUMENTS, THROWABLE
    }

    private static final class OtherLoggerOwner {
    }
}
