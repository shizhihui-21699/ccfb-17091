<?php

declare(strict_types=1);

namespace MailGuardTests;

use MailGuard\EmailAddress;
use MailGuard\ValidationException;
use MailGuard\ValidationOptions;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class EmailAddressTest extends TestCase
{
    #[DataProvider('validAddresses')]
    public function testAcceptsValidAddresses(string $input, string $expectedAscii, ?string $expectedName = null): void
    {
        $address = EmailAddress::fromUserInput($input);
        self::assertSame($expectedAscii, $address->address);
        if ($expectedName !== null) {
            self::assertSame($expectedName, $address->displayName);
        }
    }

    /**
     * @return array<string, array{0:string,1:string,2?:?string}>
     */
    public static function validAddresses(): array
    {
        return [
            'plain' => ['user@example.com', 'user@example.com'],
            'plus tag' => ['first.last+tag@sub.example.co.uk', 'first.last+tag@sub.example.co.uk'],
            'uppercase domain lowercased' => ['USER@EXAMPLE.COM', 'USER@example.com'],
            'display name with angle' => ['Alice Example <alice@example.com>', 'alice@example.com', 'Alice Example'],
            'quoted display name' => ['"Alice, Admin" <alice@example.com>', 'alice@example.com', 'Alice, Admin'],
            'idn chinese domain' => ['user@例え.jp', 'user@xn--r8jz45g.jp'],
            'idn german' => ['info@müller.example', 'info@xn--mller-kva.example'],
            'idn russian' => ['box@почта.ru', 'box@xn--80a1acny.ru'],
            'idn in angle form' => ['日本語 <info@例え.jp>', 'info@xn--r8jz45g.jp', '日本語'],
            'emoji domain' => ['hi@😀.example.com', 'hi@xn--e28h.example.com'],
            'numeric local' => ['123456789@example.com', '123456789@example.com'],
            'hyphen local' => ['a-b_c@example.com', 'a-b_c@example.com'],
        ];
    }

    #[DataProvider('injectionPayloads')]
    public function testRejectsInjectionPayloads(string $input): void
    {
        $this->expectException(ValidationException::class);
        EmailAddress::fromUserInput($input);
    }

    /**
     * @return array<string, array{0:string}>
     */
    public static function injectionPayloads(): array
    {
        return [
            'lf bcc' => ["user@example.com\nBcc: victim@evil.example"],
            'crlf bcc' => ["user@example.com\r\nBcc: victim@evil.example"],
            'cr only' => ["user@example.com\rBcc: x@evil.example"],
            'lf in local' => ["user\n@example.com"],
            'crlf after domain' => ["user@example.com\r\n\r\nBODY INJECTION"],
            'tab/nul' => ["user\x00@example.com"],
            'header via angle' => ["Alice <user@example.com>\nBcc: x@evil.example"],
            'newline in display name' => ["Bob\nInjected <bob@example.com>"],
            'encoded newline' => ["user@example.com%0d%0aBcc:%20x@evil.example"],
            'double at' => ["user@example.com@evil.example"],
            'space injection' => ["user@example.com extra@evil.example"],
            'angle break' => ["<user@example.com\n>"],
        ];
    }

    #[DataProvider('malformedAddresses')]
    public function testRejectsMalformedAddresses(string $input): void
    {
        $this->expectException(ValidationException::class);
        EmailAddress::fromUserInput($input);
    }

    public static function malformedAddresses(): array
    {
        return [
            'empty' => [''],
            'no at' => ['userexample.com'],
            'empty local' => ['@example.com'],
            'empty domain' => ['user@'],
            'leading dot' => ['.user@example.com'],
            'trailing dot local' => ['user.@example.com'],
            'double dot' => ['us..er@example.com'],
            'single label' => ['user@localhost'],
            'ip literal' => ['user@[192.0.2.1]'],
            'trailing dot domain' => ['user@example.com.'],
            'bad tld underscore' => ['user@ex_ample.com'],
            'space in local' => ['us er@example.com'],
            'idn invalid bidi-like' => ['user@a..example.com'],
        ];
    }

    public function testQuotedLocalPartRejectedByDefault(): void
    {
        $this->expectException(ValidationException::class);
        EmailAddress::fromUserInput('"a b"@example.com');
    }

    public function testQuotedLocalPartAllowedByPolicy(): void
    {
        $address = EmailAddress::fromUserInput(
            '"a b"@example.com',
            null,
            new ValidationOptions(allowQuotedLocalPart: true),
        );
        self::assertSame('"a b"@example.com', $address->address);
    }

    public function testUnicodeLocalPartRejectedWithoutSmtputf8(): void
    {
        $this->expectException(ValidationException::class);
        EmailAddress::fromUserInput('用户@example.com');
    }

    public function testUnicodeLocalPartAcceptedWithSmtputf8(): void
    {
        $address = EmailAddress::fromUserInput(
            '用户@example.com',
            null,
            new ValidationOptions(allowUnicodeLocalPart: true),
        );
        self::assertSame('用户@example.com', $address->unicodeAddress);
        // ASCII transport form keeps the Unicode local since no downgrade exists;
        // domain remains ASCII.
        self::assertStringEndsWith('@example.com', $address->address);
    }

    public function testSingleLabelDomainPolicy(): void
    {
        $address = EmailAddress::fromUserInput(
            'root@localhost',
            null,
            new ValidationOptions(allowSingleLabelDomain: true),
        );
        self::assertSame('root@localhost', $address->address);
    }

    public function testParseListHandlesCommasAndQuotes(): void
    {
        $list = EmailAddress::parseList('a@example.com, "B, C" <b@example.com>, c@example.org');
        self::assertCount(3, $list);
        self::assertSame('a@example.com', $list[0]->address);
        self::assertSame('b@example.com', $list[1]->address);
        self::assertSame('B, C', $list[1]->displayName);
        self::assertSame('c@example.org', $list[2]->address);
    }

    public function testParseListRejectsInjectedEntry(): void
    {
        $this->expectException(ValidationException::class);
        EmailAddress::parseList("a@example.com, bad@example.com\nBcc: x@evil.example");
    }

    public function testDisplayNameWithControlCharsRejected(): void
    {
        $this->expectException(ValidationException::class);
        EmailAddress::fromUserInput('user@example.com', "Alice\r\nBcc: x@evil.example");
    }

    public function testLongAddressRejected(): void
    {
        $longLocal = str_repeat('a', 65);
        $this->expectException(ValidationException::class);
        EmailAddress::fromUserInput($longLocal . '@example.com');
    }
}
