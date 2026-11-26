<?php

declare(strict_types=1);

namespace MailGuard;

/**
 * Safe construction of RFC 5322 header values.
 *
 * Every method here guarantees the returned string contains no raw CR or LF:
 * folding, when required, is performed with CRLF followed by a space by the
 * renderer, and never from input data. Callers pass plain single-line values;
 * any control character in input is rejected before encoding.
 */
final class MimeHeader
{
    /** RFC 2047 encoded words must stay at or below 75 characters including the wrapper. */
    private const MAX_WORD_LINE = 75;

    /**
     * Validate a header field name (RFC 5322 "token": 1*<any CHAR except CTLs or separators>).
     */
    public static function validateFieldName(string $name): string
    {
        if ($name === '') {
            throw ValidationException::forInput('header name', 'empty header name');
        }
        if (preg_match('/^[!-\x7E]+$/', $name) !== 1 || preg_match('/[()<>@,;:\\"\/\[\]?=]/', $name)) {
            throw ValidationException::forInput('header name', 'not a valid RFC 5322 field-name token', $name);
        }
        return $name;
    }

    /**
     * Validate a free-form header value / subject. CR, LF and NUL are always
     * rejected; other non-printable controls are rejected too. Tabs are
     * rejected in raw input and only re-introduced by our own folding.
     */
    public static function validateUnstructuredValue(string $value, string $field = 'header value'): string
    {
        if (preg_match('/[\x00-\x1F\x7F]/u', $value)) {
            throw ValidationException::forInput($field, 'contains control characters (CR/LF are forbidden in header values)', $value);
        }
        return $value;
    }

    /**
     * Encode an unstructured header (Subject, custom X- headers).
     * ASCII passes through (still control-character checked); non-ASCII is
     * RFC 2047 B-encoded and folded onto multiple lines safely.
     */
    public static function encodeUnstructured(string $value, string $field = 'header value'): string
    {
        self::validateUnstructuredValue($value, $field);

        if (preg_match('/^[\x20-\x7E]*$/', $value)) {
            return $value;
        }

        return self::encodeEncodedWord($value);
    }

    /**
     * RFC 2047 B (base64) encoding with RFC 2047 line folding.
     * Splits the UTF-8 byte stream on safe boundaries so multibyte chars
     * are never cut in half.
     */
    public static function encodeEncodedWord(string $value): string
    {
        $prefix = '=?UTF-8?B?';
        $suffix = '?=';
        // Base64 expands 3 bytes -> 4 chars; leave room for wrapper and " ".
        $maxBytesPerWord = (int)floor((self::MAX_WORD_LINE - strlen($prefix) - strlen($suffix)) * 3 / 4);

        $words = [];
        $offset = 0;
        $total = strlen($value);
        while ($offset < $total) {
            $chunk = self::safeUtf8Chunk($value, $offset, $maxBytesPerWord);
            $words[] = $prefix . base64_encode($chunk) . $suffix;
            $offset += strlen($chunk);
        }

        // Folding: CRLF SP is inserted by US, between encoded words only.
        return implode("\r\n ", $words);
    }

    /**
     * Take up to $max bytes from $value at $offset, backing off so a
     * multibyte UTF-8 sequence is never split.
     */
    private static function safeUtf8Chunk(string $value, int $offset, int $max): string
    {
        $remaining = substr($value, $offset, $max);
        // If the cut lands inside a multibyte sequence, drop the partial tail.
        $cut = strlen($remaining);
        while ($cut > 0) {
            $candidate = substr($remaining, 0, $cut);
            if (mb_check_encoding($candidate, 'UTF-8')) {
                return $candidate;
            }
            $cut--;
        }
        // Should be unreachable for valid UTF-8; fail loudly rather than emit garbage.
        throw ValidationException::forInput('header value', 'invalid UTF-8 sequence while encoding');
    }

    /**
     * Render a validated EmailAddress as a mailbox entry:
     *   Display Name <user@example.com>
     */
    public static function formatMailbox(EmailAddress $mailbox, bool $unicode = false): string
    {
        $address = $unicode ? $mailbox->unicodeAddress : $mailbox->address;
        if ($mailbox->displayName === null || $mailbox->displayName === '') {
            return $address;
        }
        return self::encodeEncodedWordIfNeeded($mailbox->displayName) . ' <' . $address . '>';
    }

    private static function encodeEncodedWordIfNeeded(string $name): string
    {
        if (preg_match('/^[\x20-\x7E]+$/', $name)) {
            if (preg_match("/^[A-Za-z0-9!#\$%&'*+=?^_`{|}~ .-]+\$/", $name)) {
                return $name;
            }
            return '"' . str_replace(['\\', '"'], ['\\\\', '\\"'], $name) . '"';
        }
        return self::encodeEncodedWord($name);
    }

    /**
     * @param list<EmailAddress> $mailboxes
     */
    public static function formatMailboxList(array $mailboxes, bool $unicode = false): string
    {
        return implode(', ', array_map(
            static fn(EmailAddress $m): string => self::formatMailbox($m, $unicode),
            $mailboxes,
        ));
    }
}
