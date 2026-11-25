<?php

declare(strict_types=1);

namespace MailGuard;

/**
 * Validation and RFC 2047 encoding of mailbox display names.
 *
 * Display names appear inside phrase or as encoded-words. They must never
 * contain CR/LF or NUL. Unicode names are normalised to NFC and encoded as
 * =?UTF-8?B?...?= tokens so legitimate international users (Chinese, Arabic,
 * emoji, etc.) keep working without weakening the injection defence.
 */
final class DisplayName
{
    public const MAX_LENGTH = 256;

    /**
     * @throws ValidationException
     */
    public static function validate(string $name): string
    {
        $name = trim($name);
        if ($name === '') {
            throw ValidationException::forInput('display name', 'empty display name');
        }

        // No ASCII control characters at all — CR, LF, tab included. Tabs are
        // legal in RFC folding whitespace, but inside a phrase they only ever
        // appear in injection payloads, so reject them.
        if (preg_match('/[\x00-\x1F\x7F]/u', $name)) {
            throw ValidationException::forInput('display name', 'contains control characters', $name);
        }

        // Normalise Unicode so visually identical spellings compare equal.
        if (class_exists(\Normalizer::class)) {
            $normalized = \Normalizer::normalize($name, \Normalizer::FORM_C);
            if ($normalized !== false) {
                $name = $normalized;
            }
        }

        if (mb_strlen($name, 'UTF-8') > self::MAX_LENGTH) {
            throw ValidationException::forInput('display name', 'exceeds ' . self::MAX_LENGTH . ' characters');
        }

        return $name;
    }

    /**
     * Render a display name for an RFC 5322 mailbox header:
     *   - plain ASCII atom-safe names appear unquoted
     *   - ASCII names needing quotes are quoted with proper backslash escaping
     *   - non-ASCII names are emitted as RFC 2047 B-encoded words
     */
    public static function encode(?string $name): string
    {
        if ($name === null || $name === '') {
            return '';
        }

        if (preg_match('/^[\x20-\x7E]+$/', $name)) {
            // Pure ASCII. Quote unless it is a clean phrase of atoms.
            if (preg_match("/^[A-Za-z0-9!#\$%&'*+=?^_`{|}~ .-]+\$/", $name) && !preg_match('/[.]{2}/', $name)) {
                return $name;
            }
            $escaped = str_replace(['\\', '"'], ['\\\\', '\\"'], $name);
            return '"' . $escaped . '"';
        }

        // Unicode: RFC 2047 encoded-word, folded at 75 chars per line.
        return MimeHeader::encodeEncodedWord($name);
    }
}
