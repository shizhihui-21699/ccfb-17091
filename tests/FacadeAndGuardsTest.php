<?php

declare(strict_types=1);

namespace MailGuardTests;

use MailGuard\EmailAddress;
use MailGuard\MailGuard;
use MailGuard\MailerException;
use MailGuard\Message;
use MailGuard\SwiftMailerMailer;
use MailGuard\ValidationException;
use PHPUnit\Framework\TestCase;

final class FacadeAndGuardsTest extends TestCase
{
    protected function tearDown(): void
    {
        MailGuard::reset();
    }

    public function testFacadeRejectsUnconfiguredMailer(): void
    {
        $this->expectException(MailerException::class);
        MailGuard::mailer();
    }

    public function testFacadeFlowEndToEnd(): void
    {
        $captured = [];
        $stub = static function (string $to, string $subject, string $body, string $headers, ?string $params) use (&$captured): bool {
            $captured[] = compact('to', 'subject', 'body', 'headers', 'params');
            return true;
        };

        MailGuard::setDefaultFrom(EmailAddress::fromUserInput('noreply@example.com', 'Site'));
        MailGuard::setDefaultMailer(new \MailGuard\NativeMailer(
            EmailAddress::fromUserInput('bounces@example.com'),
            null,
            $stub,
        ));

        MailGuard::mailer()->send(
            MailGuard::newMessage('Welcome')
                ->to(MailGuard::address('new.user+tag@example.com'))
                ->text('hello'),
        );

        self::assertCount(1, $captured);
        self::assertSame('new.user+tag@example.com', $captured[0]['to']);
        self::assertSame('-fbounces@example.com', $captured[0]['params']);
        self::assertStringContainsString('From: Site <noreply@example.com>', $captured[0]['headers']);
    }

    public function testFacadeAddressValidationRejectsInjection(): void
    {
        $this->expectException(ValidationException::class);
        MailGuard::address("a@example.com\r\nBcc: x@evil.example");
    }

    public function testSwiftAdapterGuardsOnMissingLibrary(): void
    {
        if (class_exists(\Swift_Message::class)) {
            self::markTestSkipped('Swift Mailer is installed in this environment.');
        }

        $this->expectException(MailerException::class);
        new SwiftMailerMailer(new \stdClass());
    }

    public function testMessageRejectsInjectedSubject(): void
    {
        $this->expectException(ValidationException::class);
        Message::create()->subject("Hi\r\nBcc: x@evil.example");
    }

    public function testRedactionDoesNotLeakControlChars(): void
    {
        try {
            EmailAddress::fromUserInput("a@b.com\nBcc: x@y.example");
            self::fail('Expected validation failure');
        } catch (ValidationException $e) {
            self::assertStringNotContainsString("\n", $e->getMessage());
            self::assertStringContainsString('?', $e->getMessage());
        }
    }
}
