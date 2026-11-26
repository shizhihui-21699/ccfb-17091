<?php

declare(strict_types=1);

namespace MailGuardTests;

use MailGuard\DisplayName;
use MailGuard\EmailAddress;
use MailGuard\HeaderSet;
use MailGuard\MailerException;
use MailGuard\MimeHeader;
use MailGuard\ValidationException;
use PHPUnit\Framework\TestCase;

final class HeaderEncodingTest extends TestCase
{
    public function testRejectsCrLfInSubject(): void
    {
        $this->expectException(ValidationException::class);
        MimeHeader::encodeUnstructured("Hello\r\nBcc: x@evil.example", 'subject');
    }

    public function testRejectsNulAndOtherControls(): void
    {
        $this->expectException(ValidationException::class);
        MimeHeader::encodeUnstructured("Hello\x00World", 'subject');
    }

    public function testAsciiSubjectPassesThrough(): void
    {
        self::assertSame('Password reset', MimeHeader::encodeUnstructured('Password reset', 'subject'));
    }

    public function testUnicodeSubjectIsEncodedWithoutRawControlChars(): void
    {
        $encoded = MimeHeader::encodeUnstructured('重置密码', 'subject');
        self::assertStringStartsWith('=?UTF-8?B?', $encoded);
        self::assertStringEndsWith('?=', $encoded);
        self::assertDoesNotMatchRegularExpression('/[\x00-\x1F]/', str_replace(["\r", "\n"], ['', ''], $encoded));
        // Round-trips.
        self::assertSame('重置密码', mb_decode_mimeheader($encoded));
    }

    public function testLongUnicodeValueFoldsAt75Chars(): void
    {
        $value = str_repeat('重', 60);
        $encoded = MimeHeader::encodeUnstructured($value, 'subject');
        foreach (explode("\r\n ", $encoded) as $line) {
            self::assertLessThanOrEqual(75, strlen($line));
        }
        self::assertSame($value, mb_decode_mimeheader($encoded));
    }

    public function testMultibyteSequencesAreNeverSplit(): void
    {
        $value = str_repeat('é重😀', 40);
        $encoded = MimeHeader::encodeUnstructured($value, 'subject');
        self::assertSame($value, mb_decode_mimeheader($encoded));
    }

    public function testDisplayNameRejectsControlChars(): void
    {
        $this->expectException(ValidationException::class);
        DisplayName::validate("Bob\r\nEvil: yes");
    }

    public function testUnicodeDisplayNameRoundTripInHeader(): void
    {
        $mailbox = EmailAddress::fromUserInput('alice@example.com', '爱丽丝');
        $rendered = MimeHeader::formatMailbox($mailbox);
        self::assertStringContainsString('<alice@example.com>', $rendered);
        self::assertStringContainsString('=?UTF-8?B?', $rendered);
        self::assertSame('爱丽丝 <alice@example.com>', mb_decode_mimeheader($rendered));
    }

    public function testAsciiQuotedDisplayName(): void
    {
        $mailbox = EmailAddress::fromUserInput('alice@example.com', 'Alice, Admin');
        $rendered = MimeHeader::formatMailbox($mailbox);
        self::assertSame('"Alice, Admin" <alice@example.com>', $rendered);
    }

    public function testHeaderSetRejectsReservedNames(): void
    {
        $this->expectException(MailerException::class);
        (new HeaderSet())->add('Bcc', 'x@evil.example');
    }

    public function testHeaderSetRejectsBadFieldName(): void
    {
        $this->expectException(ValidationException::class);
        (new HeaderSet())->add("X-Evil\r\nBcc", 'value');
    }

    public function testHeaderSetRejectsControlCharsInValue(): void
    {
        $this->expectException(ValidationException::class);
        (new HeaderSet())->add('X-App-Token', "abc\r\nBcc: x@evil.example");
    }

    public function testHeaderSetEncodesUnicodeValues(): void
    {
        $set = new HeaderSet();
        $set->add('X-App-Name', '我的应用');
        $lines = $set->renderLines();
        self::assertCount(1, $lines);
        self::assertStringStartsWith('X-App-Name: =?UTF-8?B?', $lines[0]);
    }
}
