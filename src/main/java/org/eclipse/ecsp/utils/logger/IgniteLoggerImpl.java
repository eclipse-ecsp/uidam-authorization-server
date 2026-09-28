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

import ch.qos.logback.classic.PatternLayout;
import org.eclipse.ecsp.entities.IgniteEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Logback 1.6 compatible implementation of the Ignite logger.
 *
 * <p>This class overrides the implementation supplied by {@code ecsp-utils} until that library
 * stops using Logback's removed {@code PatternLayout.defaultConverterMap} field.</p>
 */
public class IgniteLoggerImpl implements IgniteLogger {

    private static final String MESSAGE = "message";
    private static final Map<String, IgniteLoggerImpl> IGNITE_LOGGERS_MAP = new ConcurrentHashMap<>();

    private Logger logger;

    private IgniteLoggerImpl(Class<?> clazz) {
        PatternLayout.DEFAULT_CONVERTER_SUPPLIER_MAP.put("caller", IgniteCallerDataConverter::new);
        PatternLayout.DEFAULT_CONVERTER_SUPPLIER_MAP.put("ex", IgniteThrowableProxyConverter::new);
        PatternLayout.DEFAULT_CONVERTER_SUPPLIER_MAP.put("exception", IgniteThrowableProxyConverter::new);
        PatternLayout.DEFAULT_CONVERTER_SUPPLIER_MAP.put("throwable", IgniteThrowableProxyConverter::new);
        logger = LoggerFactory.getLogger(clazz);
    }

    /**
     * Sets the logger instance.
     *
     * @param logger the logger instance
     */
    public void setLogger(Logger logger) {
        this.logger = logger;
    }

    /**
     * Returns an Ignite logger for the requested class.
     *
     * @param clazz class that owns the logger
     * @return cached logger instance
     */
    protected static IgniteLogger getIgniteLoggerInstance(Class<?> clazz) {
        IGNITE_LOGGERS_MAP.computeIfAbsent(clazz.getName(), key -> new IgniteLoggerImpl(clazz));
        return IGNITE_LOGGERS_MAP.get(clazz.getName());
    }

    static IgniteLoggerImpl getIgniteLoggerImplInstance(Class<?> clazz) {
        IGNITE_LOGGERS_MAP.computeIfAbsent(clazz.getName(), key -> new IgniteLoggerImpl(clazz));
        return IGNITE_LOGGERS_MAP.get(clazz.getName());
    }

    @Override
    public boolean isTraceEnabled() {
        return logger.isTraceEnabled();
    }

    @Override
    public boolean isDebugEnabled() {
        return logger.isDebugEnabled();
    }

    @Override
    public boolean isInfoEnabled() {
        return logger.isInfoEnabled();
    }

    @Override
    public boolean isWarnEnabled() {
        return logger.isWarnEnabled();
    }

    @Override
    public boolean isErrorEnabled() {
        return logger.isErrorEnabled();
    }

    @Override
    public void trace(IgniteEvent event, String msg) {
        if (logger.isTraceEnabled()) {
            logger.trace(getMessageWithHeader(event, msg));
        }
    }

    @Override
    public void trace(IgniteEvent event, String format, Object... arguments) {
        if (logger.isTraceEnabled()) {
            logger.trace(getMessageWithHeader(event, format), arguments);
        }
    }

    @Override
    public void trace(IgniteEvent event, String msg, Throwable throwable) {
        if (logger.isTraceEnabled()) {
            logger.trace(getMessageWithHeader(event, msg), throwable);
        }
    }

    @Override
    public void trace(String msg) {
        if (logger.isTraceEnabled()) {
            logger.trace(msg);
        }
    }

    @Override
    public void trace(String format, Object... arguments) {
        if (logger.isTraceEnabled()) {
            logger.trace(format, arguments);
        }
    }

    @Override
    public void trace(String msg, Throwable throwable) {
        if (logger.isTraceEnabled()) {
            logger.trace(msg, throwable);
        }
    }

    @Override
    public void debug(IgniteEvent event, String msg) {
        if (logger.isDebugEnabled()) {
            logger.debug(getMessageWithHeader(event, msg));
        }
    }

    @Override
    public void debug(IgniteEvent event, String format, Object... arguments) {
        if (logger.isDebugEnabled()) {
            logger.debug(getMessageWithHeader(event, format), arguments);
        }
    }

    @Override
    public void debug(IgniteEvent event, String msg, Throwable throwable) {
        if (logger.isDebugEnabled()) {
            logger.debug(getMessageWithHeader(event, msg), throwable);
        }
    }

    @Override
    public void debug(String msg) {
        if (logger.isDebugEnabled()) {
            logger.debug(msg);
        }
    }

    @Override
    public void debug(String format, Object... arguments) {
        if (logger.isDebugEnabled()) {
            logger.debug(format, arguments);
        }
    }

    @Override
    public void debug(String msg, Throwable throwable) {
        if (logger.isDebugEnabled()) {
            logger.debug(msg, throwable);
        }
    }

    @Override
    public void info(IgniteEvent event, String msg) {
        if (logger.isInfoEnabled()) {
            logger.info(getMessageWithHeader(event, msg));
        }
    }

    @Override
    public void info(IgniteEvent event, String format, Object... arguments) {
        if (logger.isInfoEnabled()) {
            logger.info(getMessageWithHeader(event, format), arguments);
        }
    }

    @Override
    public void info(IgniteEvent event, String msg, Throwable throwable) {
        if (logger.isInfoEnabled()) {
            logger.info(getMessageWithHeader(event, msg), throwable);
        }
    }

    @Override
    public void info(String msg) {
        if (logger.isInfoEnabled()) {
            logger.info(msg);
        }
    }

    @Override
    public void info(String format, Object... arguments) {
        if (logger.isInfoEnabled()) {
            logger.info(format, arguments);
        }
    }

    @Override
    public void info(String msg, Throwable throwable) {
        if (logger.isInfoEnabled()) {
            logger.info(msg, throwable);
        }
    }

    @Override
    public void warn(IgniteEvent event, String msg) {
        logger.warn(getMessageWithHeader(event, msg));
    }

    @Override
    public void warn(IgniteEvent event, String format, Object... arguments) {
        logger.warn(getMessageWithHeader(event, format), arguments);
    }

    @Override
    public void warn(IgniteEvent event, String msg, Throwable throwable) {
        logger.warn(getMessageWithHeader(event, msg), throwable);
    }

    @Override
    public void warn(String msg) {
        logger.warn(msg);
    }

    @Override
    public void warn(String format, Object... arguments) {
        logger.warn(format, arguments);
    }

    @Override
    public void warn(String msg, Throwable throwable) {
        logger.warn(msg, throwable);
    }

    @Override
    public void error(IgniteEvent event, String msg) {
        logger.error(getMessageWithHeader(event, msg));
    }

    @Override
    public void error(IgniteEvent event, String format, Object... arguments) {
        logger.error(getMessageWithHeader(event, format), arguments);
    }

    @Override
    public void error(IgniteEvent event, String msg, Throwable throwable) {
        logger.error(getMessageWithHeader(event, msg), throwable);
    }

    @Override
    public void error(String msg) {
        logger.error(msg);
    }

    @Override
    public void error(String format, Object... arguments) {
        logger.error(format, arguments);
    }

    @Override
    public void error(String msg, Throwable throwable) {
        logger.error(msg, throwable);
    }

    private String getMessageWithHeader(IgniteEvent event, String format) {
        StringBuilder formatBuilder = new StringBuilder();
        formatBuilder.append("Timestamp:").append(event.getTimestamp());
        formatBuilder.append(" , RequestId:").append(event.getRequestId());
        formatBuilder.append(" , MessageId:").append(event.getMessageId());
        formatBuilder.append(" , BizTransactionId:").append(event.getBizTransactionId());
        formatBuilder.append(" , VehicleID:").append(event.getVehicleId());
        formatBuilder.append(" , EventID:").append(event.getEventId());
        formatBuilder.append(" , Version:").append(event.getSchemaVersion());
        formatBuilder.append(" , SourceDeviceID:").append(event.getSourceDeviceId());
        Optional<String> correlationId = Optional.ofNullable(event.getCorrelationId());
        if (correlationId.isPresent()) {
            formatBuilder.append(" , CorrelationId:").append(correlationId);
        }
        formatBuilder.append(" ,").append(MESSAGE).append(":").append(format);
        return formatBuilder.toString();
    }

    Map<String, IgniteLoggerImpl> getIgniteLoggersMap() {
        return IGNITE_LOGGERS_MAP;
    }
}