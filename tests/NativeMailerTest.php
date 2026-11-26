<?php

declare(strict_types=1);

namespace MailGuardTests;

use MailGuard\EmailAddress;
use MailGuard\MailerException;
use MailGuard\Message;
use MailGuard\NativeMailer;
use MailGuard\ValidationException;
use PHPUnit\Framework\TestCase;

final class NativeMailerTest extends TestCase
{
    /** @var list<array{to:string,subject:string,body:string,headers:string,params:?string}> */
    private array $captured = [];

    private function stubMailer(?EmailAddress $envelope = null): NativeMailer
    {
        $this->captured = [];
        $fn = function (string $to, string $subject, string $body, string $headers, ?string $params): bool {
            $this->captured[] = compact('to', 'subject', 'body', 'headers', 'params');
            return true;
        };
        return new NativeMailer($envelope, null, $fn);
    }

    private function validMessage(): Message
    {
        return Message::create()
            ->from(EmailAddress::fromUserInput('noreply@example.com', 'Example Site'))
            ->to(EmailAddress::fromUserInput('user@example.com', 'Jane User'))
            ->subject('Reset your password')
            ->text('Click this link to reset: https://example.com/reset?token=abc')
            ->addHeader('X-Request-Id', 'req-12345');
    }

    public function testSendsWithValidatedFieldsAndNoParamsByDefault(): void
    {
        $mailer = $this->stubMailer();
        $mailer->send($this->validMessage());

        self::assertCount(1, $this->captured);
        $call = $this->captured[0];
        self::assertSame('user@example.com', $call['to']);
        self::assertSame('Reset your password', $call['subject']);
        self::assertNull($call['params']);
        self::assertStringContainsString('From: Example Site <noreply@example.com>', $call['headers']);
        self::assertStringContainsString('To: Jane User <user@example.com>', $call['headers']);
        self::assertStringContainsString('X-Request-Id: req-12345', $call['headers']);
        self::assertStringContainsString('MIME-Version: 1.0', $call['headers']);
        self::assertStringContainsString('Content-Type: text/plain; charset=UTF-8', $call['headers']);
    }

    public function testEnvelopeSenderBecomesOnlyAdditionalParameter(): void
    {
        $sender = EmailAddress::fromUserInput('bounces@example.com');
        $mailer = $this->stubMailer($sender);
        $mailer->send($this->validMessage());

        self::assertSame('-fbounces@example.com', $this->captured[0]['params']);
    }

    public function testEnvelopeSenderWithIdnIsRejectedForRawFlag(): void
    {
        // An IDN envelope sender puny-codes to a plain ASCII A-label, which is
        // safe; but a Unicode local part must never reach -f.
        $idnSender = EmailAddress::fromUserInput('bounces@例え.jp');
        self::assertSame('-fbounces@xn--r8jz45g.jp', $this->invokeParams($idnSender));
    }

    private function invokeParams(EmailAddress $sender): ?string
    {
        $mailer = $this->stubMailer($sender);
        $mailer->send($this->validMessage());
        return $this->captured[0]['params'];
    }

    public function testCcAndBccReachEnvelopeAndHeaders(): void
    {
        $message = $this->validMessage()
            ->cc(EmailAddress::fromUserInput('cc@example.com'))
            ->bcc(EmailAddress::fromUserInput('bcc@example.com'));

        $this->stubMailer()->send($message);
        $call = $this->captured[0];
        self::assertSame('user@example.com, cc@example.com, bcc@example.com', $call['to']);
        self::assertStringContainsString('Cc: cc@example.com', $call['headers']);
        self::assertStringContainsString('Bcc: bcc@example.com', $call['headers']);
    }

    public function testIdnRecipientIsPunyCodedInTransport(): void
    {
        $message = Message::create()
            ->from(EmailAddress::fromUserInput('noreply@example.com'))
            ->to(EmailAddress::fromUserInput('user@例え.jp'))
            ->subject('テスト')
            ->text('本文');

        $this->stubMailer()->send($message);
        $call = $this->captured[0];
        self::assertSame('user@xn--r8jz45g.jp', $call['to']);
        self::assertStringContainsString('user@xn--r8jz45g.jp', $call['headers']);
        // Unicode subject encoded, never raw.
        self::assertStringStartsWith('=?UTF-8?B?', $call['subject']);
    }

    public function testInjectedRecipientIsRejectedBeforeMailIsCalled(): void
    {
        $this->expectException(ValidationException::class);
        EmailAddress::fromUserInput("user@example.com\r\nBcc: victim@evil.example");
        self::assertSame([], $this->captured);
    }

    public function testInjectedHeaderValueIsRejected(): void
    {
        $this->expectException(ValidationException::class);
        $this->validMessage()->addHeader('X-Evil', "val\r\nBcc: victim@evil.example");
    }

    public function testUnsendableMessageThrows(): void
    {
        $this->expectException(MailerException::class);
        $this->stubMailer()->send(
            Message::create()->from(EmailAddress::fromUserInput('a@example.com'))->subject('s')->text('b'),
        );
    }

    public function testHtmlAndTextProduceMultipartAlternative(): void
    {
        $message = $this->validMessage()->html('<p>hello</p>');
        $this->stubMailer()->send($message);
        $call = $this->captured[0];
        self::assertStringContainsString('multipart/alternative', $call['headers']);
        // Part Content-Type lines live in the MIME body.
        self::assertStringContainsString('Content-Type: text/plain; charset=UTF-8', $call['body']);
        self::assertStringContainsString('Content-Type: text/html; charset=UTF-8', $call['body']);
    }

    public function testTransportFailureWrapped(): void
    {
        $fn = static fn(): bool => false;
        $mailer = new NativeMailer(null, null, $fn);
        $this->expectException(MailerException::class);
        $mailer->send($this->validMessage());
    }
}
