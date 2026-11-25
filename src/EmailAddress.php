<?php

declare(strict_types=1);

namespace MailGuard;

/**
 * A validated mailbox: an address that has passed EmailValidator plus an
 * optional display name that has passed display-name validation.
 *
 * Objects of this class are the ONLY thing the mailers accept for
 * To/Cc/Bcc/From/Reply-To/Sender — raw user strings never reach a transport.
 */
final class EmailAddress
{
    /**
     * @param string      $address       Normalized ASCII addr-spec (IDN domain puny-coded).
     * @param string|null $displayName   Already validated display name, or null.
     * @param string      $unicodeAddress Original addr-spec when the local part is Unicode
     *                                    and SMTPUTF8 is in use; otherwise identical to $address.
     */
    private function __construct(
        public readonly string $address,
        public readonly ?string $displayName,
        public readonly string $unicodeAddress,
    ) {
    }

    /**
     * Main entry point for user-supplied "Name <user@example.com>" style input.
     *
     * @throws ValidationException
     */
    public static function fromUserInput(string $address, ?string $displayName = null, ?ValidationOptions $options = null): self
    {
        $options ??= ValidationOptions::default();
        $address = self::trimOuterWhitespace($address);
        if ($address === '') {
            throw ValidationException::forInput('email address', 'empty address', $address);
        }

        // Reject line breaks / control characters before any parsing — this is
        // the core of the header-injection defence.
        self::rejectControlChars($address, 'email address');

        $parsedName = null;
        if (preg_match('/^(.*)<([^<>]+)>$/s', $address, $m)) {
            $parsedName = trim($m[1]);
            $address = trim($m[2]);
            // Display name must not be smuggled in quotes containing control chars.
            self::rejectControlChars($parsedName, 'display name');
            // Strip MIME quoting: "Alice, Admin" -> Alice, Admin (with un-escaping).
            if (strlen($parsedName) >= 2 && $parsedName[0] === '"' && $parsedName[strlen($parsedName) - 1] === '"') {
                $inner = substr($parsedName, 1, -1);
                $parsedName = str_replace(['\\\\', '\\"'], ['\\', '"'], $inner);
            }
        }

        $name = $displayName ?? ($parsedName !== '' ? $parsedName : null);
        if ($name !== null) {
            $name = DisplayName::validate($name);
        }

        $result = EmailValidator::validate($address, $options);

        return new self($result['asciiAddress'], $name, $result['unicodeAddress']);
    }

    /** Build from already-validated parts (internal use). */
    public static function fromValidated(string $asciiAddress, ?string $validatedDisplayName, string $unicodeAddress): self
    {
        return new self($asciiAddress, $validatedDisplayName, $unicodeAddress);
    }

    /**
     * Parse a comma-separated list of mailboxes as entered by a user.
     * Used for Cc fields; never for recipients that should stay single.
     *
     * @return list<EmailAddress>
     */
    public static function parseList(string $input, ?ValidationOptions $options = null): array
    {
        $input = trim($input);
        if ($input === '') {
            return [];
        }
        // Split on commas that are not inside quotes or angle brackets.
        $parts = [];
        $depth = 0;
        $inQuote = false;
        $escaped = false;
        $buffer = '';
        foreach (mb_str_split($input, 1, 'UTF-8') as $ch) {
            if ($escaped) {
                $buffer .= $ch;
                $escaped = false;
                continue;
            }
            if ($ch === '\\') {
                $buffer .= $ch;
                $escaped = true;
                continue;
            }
            if ($ch === '"') {
                $inQuote = !$inQuote;
                $buffer .= $ch;
                continue;
            }
            if (!$inQuote) {
                if ($ch === '<') {
                    $depth++;
                } elseif ($ch === '>') {
                    $depth = max(0, $depth - 1);
                } elseif ($ch === ',' && $depth === 0) {
                    $parts[] = $buffer;
                    $buffer = '';
                    continue;
                }
            }
            $buffer .= $ch;
        }
        if (trim($buffer) !== '') {
            $parts[] = $buffer;
        }

        $out = [];
        foreach ($parts as $part) {
            if (trim($part) === '') {
                continue;
            }
            $out[] = self::fromUserInput($part, null, $options);
        }
        return $out;
    }

    public static function trimOuterWhitespace(string $s): string
    {
        // Trim spaces, tabs, non-breaking spaces and other Unicode whitespace,
        // but NOT CR/LF — those are rejected explicitly above.
        return preg_replace('/^[\x{0020}\x{0009}\x{00A0}\x{FEFF}]+|[\x{0020}\x{0009}\x{00A0}\x{FEFF}]+$/u', '', $s) ?? $s;
    }

    public static function rejectControlChars(string $s, string $field): void
    {
        if (preg_match('/[\x00-\x1F\x7F]/u', $s)) {
            throw ValidationException::forInput($field, 'contains control characters (CR/LF/NUL are forbidden)', $s);
        }
    }
}
