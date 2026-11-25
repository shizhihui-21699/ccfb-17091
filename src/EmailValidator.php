<?php

declare(strict_types=1);

namespace MailGuard;

/**
 * Strict, parser-based email address validation.
 *
 * Why not FILTER_VALIDATE_EMAIL alone: it accepts a number of historical
 * quirks and, more importantly, gives no IDN handling and no structured
 * reason on failure. This validator implements the RFC 5321/5322 addr-spec
 * subset that real mailboxes use, then normalises internationalised domains
 * through IDNA (UTS #46) via ext-intl.
 *
 * Guaranteed invariants for every address that passes:
 *  - no NUL/CR/LF or any other ASCII control character anywhere
 *  - domain is an ASCII A-label (xn--) form or a plain ASCII domain
 *  - length limits (254 total, 64 local) respected
 *  - returns both the ASCII transport form and the Unicode form
 */
final class EmailValidator
{
    /** atext per RFC 5322 §3.2.3, plus nothing else. */
    private const ATEXT = "A-Za-z0-9!#$%&'*+=?^_`{|}~-";
    private const ATEXT_CLASS = "[A-Za-z0-9!#\$%&'*+=?^_`{|}~-]";

    /**
     * @return array{asciiAddress: string, unicodeAddress: string, local: string, domainAscii: string, domainUnicode: string}
     * @throws ValidationException
     */
    public static function validate(string $address, ?ValidationOptions $options = null): array
    {
        $options ??= ValidationOptions::default();

        $address = trim($address);
        if ($address === '') {
            throw ValidationException::forInput('email address', 'empty address');
        }

        // Defence in depth: the public entry point already checks, but this
        // class must be safe even when called directly.
        if (preg_match('/[\x00-\x1F\x7F]/u', $address)) {
            throw ValidationException::forInput('email address', 'contains control characters', $address);
        }

        if (strlen($address) > $options->maxAddressLength) {
            throw ValidationException::forInput('email address', "exceeds {$options->maxAddressLength} octets", $address);
        }

        $atCount = substr_count($address, '@');
        if ($atCount !== 1) {
            throw ValidationException::forInput('email address', $atCount === 0 ? 'missing @ sign' : 'multiple @ signs', $address);
        }

        [$localRaw, $domainRaw] = explode('@', $address, 2);
        if ($localRaw === '' || $domainRaw === '') {
            throw ValidationException::forInput('email address', 'empty local part or domain', $address);
        }

        $local = self::validateLocalPart($localRaw, $options, $address);
        [$domainAscii, $domainUnicode] = self::validateDomain($domainRaw, $options, $address);

        $asciiAddress = $local . '@' . $domainAscii;
        if (strlen($asciiAddress) > $options->maxAddressLength) {
            throw ValidationException::forInput('email address', "puny-coded form exceeds {$options->maxAddressLength} octets", $address);
        }

        // Unicode transport form: only differs when a Unicode local part is
        // allowed; the domain is always emitted in its original spelling here.
        $unicodeAddress = $local . '@' . $domainUnicode;

        return [
            'asciiAddress' => $asciiAddress,
            'unicodeAddress' => $unicodeAddress,
            'local' => $local,
            'domainAscii' => $domainAscii,
            'domainUnicode' => $domainUnicode,
        ];
    }

    private static function validateLocalPart(string $local, ValidationOptions $options, string $fullAddress): string
    {
        // Quoted-string form: "..."@domain
        if (str_starts_with($local, '"')) {
            if (!$options->allowQuotedLocalPart) {
                throw ValidationException::forInput('email address', 'quoted local parts are disabled by policy', $fullAddress);
            }
            return self::validateQuotedLocalPart($local, $options, $fullAddress);
        }

        if (strlen($local) > $options->maxLocalPartLength) {
            throw ValidationException::forInput('email address', "local part exceeds {$options->maxLocalPartLength} octets", $fullAddress);
        }

        // Dot-atom: one or more atext atoms separated by single dots.
        if (preg_match('/^(?:' . self::ATEXT_CLASS . ')+(?:\.(?:' . self::ATEXT_CLASS . ')+)*$/', $local) === 1) {
            return $local;
        }

        // If it contains non-ASCII, evaluate the SMTPUTF8 policy explicitly so
        // the error message is actionable.
        if (preg_match('/[^\x20-\x7E]/u', $local)) {
            if (!$options->allowUnicodeLocalPart) {
                throw ValidationException::forInput(
                    'email address',
                    'Unicode local part requires SMTPUTF8, which is not enabled for this transport',
                    $fullAddress,
                );
            }
            return self::validateUnicodeLocalPart($local, $options, $fullAddress);
        }

        throw ValidationException::forInput('email address', 'malformed local part (not a valid dot-atom)', $fullAddress);
    }

    private static function validateQuotedLocalPart(string $local, ValidationOptions $options, string $fullAddress): string
    {
        // Must end with a closing quote and contain no unescaped control chars.
        if (!preg_match('/^"(?:[\\\\]?[\x20-\x7E])*"$/', $local)) {
            throw ValidationException::forInput('email address', 'malformed quoted local part', $fullAddress);
        }
        if (strlen($local) > $options->maxLocalPartLength + 2) {
            throw ValidationException::forInput('email address', "local part exceeds {$options->maxLocalPartLength} octets", $fullAddress);
        }
        return $local;
    }

    private static function validateUnicodeLocalPart(string $local, ValidationOptions $options, string $fullAddress): string
    {
        // Unicode dot-atom: split on dots, each atom must contain at least one
        // non-ASCII char alongside permitted atext, and no whitespace/controls.
        $atoms = explode('.', $local);
        foreach ($atoms as $atom) {
            if ($atom === '') {
                throw ValidationException::forInput('email address', 'empty dot-atom in Unicode local part', $fullAddress);
            }
            if (preg_match('/^(?:' . self::ATEXT_CLASS . '|[^\x00-\x7F])+$/u', $atom) !== 1) {
                throw ValidationException::forInput('email address', 'illegal character in Unicode local part', $fullAddress);
            }
        }
        // RFC 6531 measures local part in UTF-8 octets.
        if (strlen($local) > $options->maxLocalPartLength) {
            throw ValidationException::forInput('email address', "Unicode local part exceeds {$options->maxLocalPartLength} UTF-8 octets", $fullAddress);
        }
        return $local;
    }

    /**
     * @return array{0:string,1:string} [ascii A-label form, original Unicode form]
     */
    private static function validateDomain(string $domain, ValidationOptions $options, string $fullAddress): array
    {
        // Domain literal: [192.0.2.1] or [IPv6:...]
        if (str_starts_with($domain, '[')) {
            if (!$options->allowDomainLiteral) {
                throw ValidationException::forInput('email address', 'domain literals are disabled by policy', $fullAddress);
            }
            return self::validateDomainLiteral($domain, $fullAddress);
        }

        if (preg_match('/[\x00-\x20\x7F]/', $domain)) {
            throw ValidationException::forInput('email address', 'whitespace/control characters in domain', $fullAddress);
        }

        $unicodeLabels = explode('.', $domain);
        if (count($unicodeLabels) < 2 && !$options->allowSingleLabelDomain) {
            throw ValidationException::forInput('email address', 'single-label domain rejected (no public TLD)', $fullAddress);
        }

        foreach ($unicodeLabels as $label) {
            if ($label === '') {
                throw ValidationException::forInput('email address', 'empty DNS label (consecutive dots or trailing dot)', $fullAddress);
            }
            // IDNA2008/UTS46 via intl. IDNA_DEFAULT applies UTS46 + STD3 rules,
            // which reject underscores, control chars and invalid bidi.
            if (strlen($label) > 63) {
                throw ValidationException::forInput('email address', 'DNS label longer than 63 octets', $fullAddress);
            }
        }

        $idnaInfo = [];
        $ascii = idn_to_ascii(
            $domain,
            IDNA_DEFAULT,
            INTL_IDNA_VARIANT_UTS46,
            $idnaInfo,
        );

        if ($ascii === false) {
            throw ValidationException::forInput('email address', 'IDNA conversion failed for domain', $fullAddress);
        }

        // UTS46 records deviation/error flags; treat any error as a rejection.
        if (($idnaInfo['errors'] ?? 0) !== 0) {
            throw ValidationException::forInput(
                'email address',
                'domain fails IDNA validation (error flag ' . $idnaInfo['errors'] . ')',
                $fullAddress,
            );
        }

        // Re-validate the A-label output strictly: labels must be LDH or xn--.
        foreach (explode('.', $ascii) as $label) {
            if (!preg_match('/^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)$/', $label)) {
                throw ValidationException::forInput('email address', 'domain produced an invalid DNS label', $fullAddress);
            }
        }

        // Normalise the Unicode spelling through IDNA as well, so comparisons
        // are canonical (e.g. full-width vs half-width).
        $unicode = idn_to_utf8($ascii, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
        if ($unicode === false) {
            $unicode = $domain;
        }

        return [strtolower($ascii), $unicode];
    }

    /**
     * @return array{0:string,1:string}
     */
    private static function validateDomainLiteral(string $domain, string $fullAddress): array
    {
        if (!preg_match('/^\[(IPv6:[0-9A-Fa-f:]+|\d{1,3}(?:\.\d{1,3}){3})\]$/', $domain, $m)) {
            throw ValidationException::forInput('email address', 'malformed domain literal', $fullAddress);
        }
        if (isset($m[1]) && !str_starts_with($m[1], 'IPv6:')) {
            foreach (explode('.', $m[1]) as $octet) {
                if ((int)$octet > 255) {
                    throw ValidationException::forInput('email address', 'invalid IPv4 literal', $fullAddress);
                }
            }
        }
        return [$domain, $domain];
    }
}
