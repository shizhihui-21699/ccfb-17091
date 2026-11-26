<?php

declare(strict_types=1);

namespace MailGuardTests;

use MailGuard\EmailAddress;
use MailGuard\Message;
use MailGuard\PhpMailerMailer;
use MailGuard\SymfonyMailerMailer;
use PHPMailer\PHPMailer\PHPMailer;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Mailer\Envelope;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\RawMessage;

final class AdapterTest extends TestCase
{
    private function message(): Message
    {
        return Message::create()
            ->from(EmailAddress::fromUserInput('noreply@example.com', 'Example'))
            ->to(EmailAddress::fromUserInput('user@例え.jp', 'ユーザー'))
            ->cc(EmailAddress::fromUserInput('cc@example.com'))
            ->subject('重置密码 / Reset')
            ->text('plain body')
            ->html('<p>html body</p>')
            ->addHeader('X-Request-Id', 'abc-123');
    }

    public function testPhpMailerAdapterPreparesValidatedMessage(): void
    {
        // PHPMailer subclass whose transport methods never touch an MTA,
        // injected through the adapter's protected creation seam.
        $stubMailer = new class(true) extends PHPMailer {
            public function mailSend($header, $body): bool
            {
                return true;
            }

            public function sendmailSend($header, $body): bool
            {
                return true;
            }
        };

        $adapter = new class(EmailAddress::fromUserInput('bounces@example.com'), $stubMailer) extends PhpMailerMailer {
            public function __construct(
                private ?EmailAddress $envelope,
                private PHPMailer $injected,
            ) {
                parent::__construct($envelope);
            }

            protected function createPhpMailer(): PHPMailer
            {
                return $this->injected;
            }
        };

        $adapter->send($this->message());

        // Envelope sender pinned to config, not request data.
        self::assertSame('bounces@example.com', $stubMailer->Sender);
        // IDN domain puny-coded; no raw CR/LF anywhere in configured fields.
        self::assertSame('user@xn--r8jz45g.jp', $stubMailer->getToAddresses()[0][0]);
        self::assertSame('cc@example.com', $stubMailer->getCcAddresses()[0][0]);
        self::assertSame('noreply@example.com', $stubMailer->From);
        self::assertStringContainsString('重置密码 / Reset', $stubMailer->Subject);
        self::assertStringContainsString('<p>html body</p>', $stubMailer->Body);
        self::assertSame('plain body', $stubMailer->AltBody);

        $customHeaderValues = array_column($stubMailer->getCustomHeaders(), 1, 0);
        self::assertSame('abc-123', $customHeaderValues['X-Request-Id']);
    }

    public function testSymfonyAdapterPinsEnvelopeAndValidatedRecipients(): void
    {
        $transport = new class implements MailerInterface {
            public ?RawMessage $message = null;
            public ?Envelope $envelope = null;

            public function send(RawMessage $message, ?Envelope $envelope = null): void
            {
                $this->message = $message;
                $this->envelope = $envelope;
            }
        };

        $mailer = new SymfonyMailerMailer(
            $transport,
            EmailAddress::fromUserInput('bounces@example.com'),
        );
        $mailer->send($this->message());

        self::assertNotNull($transport->envelope);
        self::assertSame('bounces@example.com', $transport->envelope->getSender()->getAddress());
        $recipientAddresses = array_map(
            static fn($a): string => $a->getAddress(),
            $transport->envelope->getRecipients(),
        );
        self::assertContains('user@xn--r8jz45g.jp', $recipientAddresses);
        self::assertContains('cc@example.com', $recipientAddresses);

        $rendered = $transport->message->toString();
        self::assertStringContainsString('From: Example <noreply@example.com>', $rendered);
        self::assertStringContainsString('user@xn--r8jz45g.jp', $rendered);
        self::assertStringContainsString('X-Request-Id: abc-123', $rendered);
        // Symfony may choose Q or B encoded-word; accept either, but require
        // an encoded subject (never a raw multibyte header value).
        self::assertMatchesRegularExpression('/Subject: =\?utf-8\?[BQ]\?/i', $rendered);
        // No bare CR or LF: every line break is a proper CRLF.
        self::assertDoesNotMatchRegularExpression('/[^\r]\n/', $rendered);
        self::assertDoesNotMatchRegularExpression("/\r[^\n]/", $rendered);
    }

    public function testSymfonyAdapterWithoutExplicitEnvelopeUsesFrom(): void
    {
        $transport = new class implements MailerInterface {
            public ?Envelope $envelope = null;

            public function send(RawMessage $message, ?Envelope $envelope = null): void
            {
                $this->envelope = $envelope;
            }
        };

        (new SymfonyMailerMailer($transport))->send(
            Message::create()
                ->from(EmailAddress::fromUserInput('noreply@example.com'))
                ->to(EmailAddress::fromUserInput('user@example.com'))
                ->subject('s')
                ->text('b'),
        );

        self::assertSame('noreply@example.com', $transport->envelope->getSender()->getAddress());
    }
}
