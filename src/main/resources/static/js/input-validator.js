/**
 * Client-side input validation to detect dangerous content
 * (scripts, HTML tags, SQL injection) before form submission.
 *
 * This mirrors the server-side InputSanitizer.java patterns.
 * Server-side validation is kept as a security backstop.
 */
var InputValidator = (function () {
    'use strict';

    var DANGEROUS_PATTERN = new RegExp(
        '<[^>]*>'                                           // HTML/XML tags
        + '|<script[^>]*>[\\s\\S]*?<\\/script>'          // script blocks (including multiline)
        + '|javascript\\s*:'                                // javascript: protocol
        + '|on\\w+\\s*='                                    // inline event handlers
        + '|--'                                             // SQL comment
        + '|;\\s*(?:DROP|ALTER|INSERT|UPDATE|DELETE|EXEC|UNION|CREATE|TRUNCATE)' // SQL statements
        + '|\\b(?:OR|AND)\\s*\\d+\\s*=\\s*\\d+'             // boolean injection (with or without spaces)
        + "|'\\s*(?:OR|AND)(?:\\s|\\d)"                       // quote-prefixed injection: 'or1, ' OR ...
        + '|\\bUNION\\s+(?:ALL\\s+)?SELECT\\b'              // UNION SELECT
        + '|\\/\\*[\\s\\S]*?\\*\\/'                      // SQL block comments (including multiline)
        + '|&#\\d+;?'                                       // HTML numeric entities
        + '|&#x[0-9a-fA-F]+;?'                             // HTML hex entities
        + '|\\\\x[0-9a-fA-F]{2}',                          // hex escape sequences
        'i'
    );

    var INVALID_INPUT_MSG = 'Invalid input. Please use only valid characters.';

    /**
     * Checks if a single value is safe (no dangerous patterns).
     * Returns true if safe, false if dangerous content detected.
     */
    function isSafe(value) {
        if (value === null || value === undefined || value === '') {
            return true;
        }
        return !DANGEROUS_PATTERN.test(value);
    }

    /**
     * Validates a single input field. Shows/hides an inline error message.
     * Returns true if safe.
     */
    function validateField(inputElement, errorElementId) {
        var value = inputElement.value;
        var errorEl = document.getElementById(errorElementId);
        if (!isSafe(value)) {
            if (errorEl) {
                errorEl.textContent = INVALID_INPUT_MSG;
                errorEl.style.display = 'block';
            }
            return false;
        }
        if (errorEl) {
            errorEl.textContent = '';
            errorEl.style.display = 'none';
        }
        return true;
    }

    /**
     * Validates multiple fields by their IDs. Each field needs
     * a corresponding error element with id = fieldId + 'Error'.
     * Returns true if ALL fields are safe.
     */
    function validateFields(fieldIds) {
        var allSafe = true;
        for (var i = 0; i < fieldIds.length; i++) {
            var el = document.getElementById(fieldIds[i]);
            if (el) {
                var safe = validateField(el, fieldIds[i] + 'Error');
                if (!safe) {
                    allSafe = false;
                }
            }
        }
        return allSafe;
    }

    /**
     * Attaches real-time validation to input fields. Shows error
     * on blur if dangerous content is typed.
     */
    function attachValidation(fieldIds) {
        for (var i = 0; i < fieldIds.length; i++) {
            (function (fieldId) {
                var el = document.getElementById(fieldId);
                if (!el) {
                    return;
                }
                el.addEventListener('blur', function () {
                    validateField(el, fieldId + 'Error');
                });
                el.addEventListener('input', function () {
                    if (!isSafe(el.value)) {
                        validateField(el, fieldId + 'Error');
                    } else {
                        var errorEl = document.getElementById(fieldId + 'Error');
                        if (errorEl) {
                            errorEl.textContent = '';
                            errorEl.style.display = 'none';
                        }
                    }
                });
            })(fieldIds[i]);
        }
    }

    return {
        isSafe: isSafe,
        validateField: validateField,
        validateFields: validateFields,
        attachValidation: attachValidation,
        INVALID_INPUT_MSG: INVALID_INPUT_MSG
    };
})();
