<?php

declare(strict_types=1);

namespace MailGuard;

/**
 * Immutable policy knobs for address/header validation.
 *
 * Defaults are deliberately strict for a website that sends password reset
 * and notification mail: single-label domains and IP-literal domains are
 * rejected, Unicode local parts (SMTPUTF8) are off unless the transport is
 * known to support them.
 */
final class ValidationOptions
{
    public function __construct(
        /** Permit non-ASCII characters in the local part (requires SMTPUTF8 end-to-end). */
        public readonly bool $allowUnicodeLocalPart = false,
        /** Permit domains without a dot, e.g. "root@localhost". Off for public web mail. */
        public readonly bool $allowSingleLabelDomain = false,
        /** Permit domain literals such as user@[192.0.2.1] / user@[IPv6:::1]. */
        public readonly bool $allowDomainLiteral = false,
        /** Permit quoted-string local parts ("a b"@example.com). Rare on consumer sites. */
        public readonly bool $allowQuotedLocalPart = false,
        /** Maximum total length of an addr-spec (RFC 5321 limit is 254 octets). */
        public readonly int $maxAddressLength = 254,
        /** Maximum local-part length (RFC 5321 limit is 64 octets). */
        public readonly int $maxLocalPartLength = 64,
    ) {
    }

    public static function default(): self
    {
        return new self();
    }

    /**
     * For transports that negotiated SMTPUTF8: Unicode local parts are kept
     * verbatim instead of being rejected.
     */
    public function withUnicodeLocalPart(bool $allowed): self
    {
        return new self(
            $allowed,
            $this->allowSingleLabelDomain,
            $this->allowDomainLiteral,
            $this->allowQuotedLocalPart,
            $this->maxAddressLength,
            $this->maxLocalPartLength,
        );
    }
}
