<?php

declare(strict_types=1);

namespace MailGuard;

/**
 * Thrown when an email address, display name or header value cannot be
 * validated. Always carries the reason so audit logs can explain rejections.
 */
class ValidationException extends MailGuardException
{
    public static function forInput(string $field, string $reason, ?string $input = null): self
    {
        $safeInput = $input === null ? '' : sprintf(' (input: %s)', self::redact($input));
        return new self(sprintf('Rejected %s: %s%s', $field, $reason, $safeInput));
    }

    /** Never log raw attacker-controlled verbatim at full length / with control chars. */
    public static function redact(string $input): string
    {
        $shown = preg_replace('/[\x00-\x1F\x7F]/u', '?', $input) ?? '';
        if (strlen($shown) > 80) {
            $shown = substr($shown, 0, 77) . '...';
        }
        return '"' . $shown . '"';
    }
}
