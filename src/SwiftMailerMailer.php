<?php

declare(strict_types=1);

namespace MailGuard;

/**
 * Adapter for legacy Swift Mailer 5/6 (Swift_Message / Swift_Mailer).
 *
 * The library is end-of-life and is not a Composer dependency of MailGuard,
 * so this adapter is written against its long-stable public API and guards
 * on class existence. New projects should use SymfonyMailerMailer; this
 * class exists so legacy sites get the same validation boundary while they
 * migrate.
 *
 * As everywhere in MailGuard, only validated EmailAddress/HeaderSet objects
 * cross the boundary; Swift's own header validation is defence in depth, not
 * the primary control.
 */
final class SwiftMailerMailer implements Mailer
{
    /**
     * @param object             $swiftMailer    An instance of Swift_Mailer.
     * @param EmailAddress|null  $envelopeSender Fixed bounce/return-path from config.
     */
    public function __construct(
        private readonly object $swiftMailer,
        private readonly ?EmailAddress $envelopeSender = null,
        private readonly ?MailLogger $logger = null,
    ) {
        if (!class_exists(\Swift_Message::class)) {
            throw new MailerException('Swift Mailer (Swift_Message) is not installed; use SymfonyMailerMailer on new projects');
        }
    }

    public function send(Message $message): void
    {
        $message->assertSendable();
        $logger = $this->logger ?? new NullLogger();

        $swift = new \Swift_Message();

        $from = $message->getFrom();
        $swift->setFrom([$from->address => $from->displayName ?? $from->address]);

        if ($message->getReplyTo() !== null) {
            $r = $message->getReplyTo();
            $swift->setReplyTo([$r->address => $r->displayName ?? $r->address]);
        }

        $to = [];
        foreach ($message->getTo() as $r) {
            $to[$r->address] = $r->displayName ?? $r->address;
        }
        $swift->setTo($to);

        if ($message->getCc() !== []) {
            $cc = [];
            foreach ($message->getCc() as $r) {
                $cc[$r->address] = $r->displayName ?? $r->address;
            }
            $swift->setCc($cc);
        }
        if ($message->getBcc() !== []) {
            $bcc = [];
            foreach ($message->getBcc() as $r) {
                $bcc[$r->address] = $r->displayName ?? $r->address;
            }
            $swift->setBcc($bcc);
        }

        $swift->setSubject($message->getSubject());

        if ($message->getHtmlBody() !== '' && $message->getTextBody() !== '') {
            $swift->setBody($message->getHtmlBody(), 'text/html');
            $swift->addPart($message->getTextBody(), 'text/plain');
        } elseif ($message->getHtmlBody() !== '') {
            $swift->setBody($message->getHtmlBody(), 'text/html');
        } else {
            $swift->setBody($message->getTextBody(), 'text/plain');
        }

        foreach ($message->getCustomHeaders()->all() as $h) {
            // Swift_Message::addTextHeader performs RFC validation itself;
            // values are already CR/LF-free from HeaderSet.
            $swift->getHeaders()->addTextHeader($h['name'], $h['value']);
        }

        if ($this->envelopeSender !== null) {
            // ReturnPath drives the sendmail -f / SMTP MAIL FROM address.
            $swift->setReturnPath($this->envelopeSender->address);
        }

        $logger->info('SwiftMailerMailer::send', [
            'to' => array_map(static fn(EmailAddress $a): string => $a->address, $message->getTo()),
        ]);

        $failures = [];
        $sent = $this->swiftMailer->send($swift, $failures);
        if ($sent === 0 || $failures !== []) {
            throw new MailerException(
                'Swift Mailer delivered to zero recipients; failures: ' . implode(', ', $failures),
            );
        }
    }
}
