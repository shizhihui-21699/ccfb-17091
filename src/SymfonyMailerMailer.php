<?php

declare(strict_types=1);

namespace MailGuard;

use Symfony\Component\Mailer\Envelope;
use Symfony\Component\Mailer\Exception\ExceptionInterface as SymfonyMailerException;
use Symfony\Component\Mailer\MailerInterface as SymfonyMailerInterface;
use Symfony\Component\Mime\Address as SymfonyAddress;
use Symfony\Component\Mime\Email;
use Symfony\Component\Mime\Header\UnstructuredHeader;

/**
 * Adapter over symfony/mailer. Symfony's MIME component already parses and
 * validates addresses itself; our layer guarantees that only MailGuard-
 * validated value objects cross the boundary, and pins the Envelope so the
 * bounce/return-path address can never be influenced by request data.
 */
final class SymfonyMailerMailer implements Mailer
{
    /**
     * @param SymfonyMailerInterface $transport      A configured Symfony transport (SMTP/SES/null…).
     * @param EmailAddress|null      $envelopeSender Fixed envelope sender from application config.
     */
    public function __construct(
        private readonly SymfonyMailerInterface $transport,
        private readonly ?EmailAddress $envelopeSender = null,
        private readonly ?MailLogger $logger = null,
    ) {
    }

    public function send(Message $message): void
    {
        $message->assertSendable();
        $logger = $this->logger ?? new NullLogger();

        $email = new Email();

        $from = $message->getFrom();
        $email->from(new SymfonyAddress($from->address, $from->displayName ?? ''));

        if ($message->getSender() !== null) {
            $s = $message->getSender();
            $email->sender(new SymfonyAddress($s->address, $s->displayName ?? ''));
        }
        if ($message->getReplyTo() !== null) {
            $r = $message->getReplyTo();
            $email->replyTo(new SymfonyAddress($r->address, $r->displayName ?? ''));
        }

        $email->to(...array_map([self::class, 'toSymfonyAddress'], $message->getTo()));
        if ($message->getCc() !== []) {
            $email->cc(...array_map([self::class, 'toSymfonyAddress'], $message->getCc()));
        }
        if ($message->getBcc() !== []) {
            $email->bcc(...array_map([self::class, 'toSymfonyAddress'], $message->getBcc()));
        }

        $email->subject($message->getSubject());

        if ($message->getTextBody() !== '') {
            $email->text($message->getTextBody());
        }
        if ($message->getHtmlBody() !== '') {
            $email->html($message->getHtmlBody());
        }

        foreach ($message->getCustomHeaders()->all() as $h) {
            // UnstructuredHeader performs its own token/encoding checks on top.
            $email->getHeaders()->add(new UnstructuredHeader($h['name'], $h['value']));
        }

        // Pin the envelope: sender from fixed config, recipients from the
        // validated To/Cc/Bcc set. Without this, Symfony derives it from
        // headers — safe, but pinning removes all ambiguity.
        $envelopeSender = $this->envelopeSender ?? $from;
        $allRecipients = array_merge($message->getTo(), $message->getCc(), $message->getBcc());
        $envelope = new Envelope(
            new SymfonyAddress($envelopeSender->address),
            array_map(
                static fn(EmailAddress $a): SymfonyAddress => new SymfonyAddress($a->address),
                $allRecipients,
            ),
        );

        $logger->info('SymfonyMailerMailer::send', [
            'to' => array_map(static fn(EmailAddress $a): string => $a->address, $message->getTo()),
        ]);

        try {
            $this->transport->send($email, $envelope);
        } catch (SymfonyMailerException $e) {
            throw new MailerException('Symfony Mailer failure: ' . $e->getMessage(), 0, $e);
        }
    }

    private static function toSymfonyAddress(EmailAddress $a): SymfonyAddress
    {
        return new SymfonyAddress($a->address, $a->displayName ?? '');
    }
}
