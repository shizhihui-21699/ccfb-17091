<?php

declare(strict_types=1);

namespace MailGuardTests;

use MailGuard\EmailAddress;
use MailGuard\Message;
use MailGuard\MimeBody;
use MailGuard\ValidationException;
use MailGuard\ValidationOptions;
use PHPUnit\Framework\TestCase;

final class EdgeCaseTest extends TestCase
{
    public function testIdnaErrorFlagRejectsLookalikeDomain(): void
    {
        // Underscore is illegal in DNS labels; UTS46 records an error.
        $this->expectException(ValidationException::class);
        EmailAddress::fromUserInput('user@ex_ample.com');
    }

    public function testIdnRoundTripIsCanonical(): void
    {
        // Full-width ASCII in the domain is a UTS46 deviation: it normalises
        // to plain ASCII "muller" (no xn-- needed), proving canonicalisation.
        $a = EmailAddress::fromUserInput('user@ｍｕｌｌｅｒ.example');
        self::assertSame('user@muller.example', $a->address);
    }

    public function testOverlongAddressRejected(): void
    {
        // Build an addr-spec that exceeds the 254-octet SMTP limit.
        $local = str_repeat('a', 64);
        $domain = str_repeat('example.', 28) . 'com';
        $this->expectException(ValidationException::class);
        EmailAddress::fromUserInput($local . '@' . $domain);
    }

    public function testOverlongDnsLabelRejected(): void
    {
        $this->expectException(ValidationException::class);
        EmailAddress::fromUserInput('user@' . str_repeat('a', 64) . '.com');
    }

    public function testBodyNewlinesCannotEscapeIntoHeaders(): void
    {
        // A body containing header-shaped text must stay inside the MIME part.
        $message = Message::create()
            ->from(EmailAddress::fromUserInput('a@example.com'))
            ->to(EmailAddress::fromUserInput('b@example.com'))
            ->subject('s')
            ->text("line1\r\nBcc: attacker@evil.example\r\nline2");

        $composed = MimeBody::compose($message);
        // Quoted-printable turns CR/LF into =0D/=0A, so no raw CRLF-prefixed
        // header line can appear in the rendered body.
        self::assertStringNotContainsString("\r\nBcc: attacker@evil.example", $composed['body']);
        self::assertStringContainsString('=0ABcc: attacker@evil.example', $composed['body']);
    }

    public function testNulByteRejectedEverywhere(): void
    {
        $this->expectException(ValidationException::class);
        EmailAddress::fromUserInput("ab\x00c@example.com");
    }

    public function testBareCarriageReturnRejected(): void
    {
        $this->expectException(ValidationException::class);
        EmailAddress::fromUserInput("a@example.com\rBcc: x@evil.example");
    }

    public function testWhitespaceTrimmingDoesNotHideInjection(): void
    {
        // Leading/trailing spaces are trimmed but inner CR/LF still rejected.
        $this->expectException(ValidationException::class);
        EmailAddress::fromUserInput("  a@example.com\nBcc: x@evil.example  ");
    }

    public function testValidAddressesWithAllowedQuotedLocalPartRoundTrip(): void
    {
        $opts = new ValidationOptions(allowQuotedLocalPart: true);
        $a = EmailAddress::fromUserInput('"a..b"@example.com', null, $opts);
        self::assertSame('"a..b"@example.com', $a->address);
    }

    public function testDomainLiteralRejectedByDefaultAndAllowedByPolicy(): void
    {
        $this->expectException(ValidationException::class);
        EmailAddress::fromUserInput('user@[192.0.2.1]');
    }

    public function testDomainLiteralAllowedByPolicy(): void
    {
        $opts = new ValidationOptions(allowDomainLiteral: true);
        $a = EmailAddress::fromUserInput('user@[192.0.2.1]', null, $opts);
        self::assertSame('user@[192.0.2.1]', $a->address);
    }

    public function testInvalidIpv4LiteralRejectedEvenWhenEnabled(): void
    {
        $opts = new ValidationOptions(allowDomainLiteral: true);
        $this->expectException(ValidationException::class);
        EmailAddress::fromUserInput('user@[999.0.2.1]', null, $opts);
    }

    public function testEmptyAndWhitespaceOnlyRejected(): void
    {
        $this->expectException(ValidationException::class);
        EmailAddress::fromUserInput('   ');
    }
}
