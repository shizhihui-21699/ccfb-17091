<?php

declare(strict_types=1);

namespace MailGuard;

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception as PHPMailerException;

/**
 * Adapter over PHPMailer that only accepts pre-validated Message objects.
 *
 * PHPMailer performs its own address checks and (in modern versions) an
 * isShellSafe() guard on the -f envelope sender, but this adapter does not
 * rely on those alone: every address and header value has already passed
 * MailGuard validation, and no caller-supplied string is forwarded into
 * PHPMailer's additional-parameter machinery. The envelope sender is fixed
 * to the application-configured validated address.
 *
 * Not declared final so tests can override createPhpMailer() with a stub.
 */
class PhpMailerMailer implements Mailer
{
    /**
     * @param EmailAddress|null $envelopeSender Fixed -f sender (application config, never request data).
     * @param \Closure|null     $configurator   Optional fn(PHPMailer $p): void for SMTP host/auth setup.
     *                                          It may configure transport only, never addresses.
     */
    public function __construct(
        private readonly ?EmailAddress $envelopeSender = null,
        private readonly ?\Closure $configurator = null,
        private readonly ?MailLogger $logger = null,
    ) {
    }

    public function send(Message $message): void
    {
        $message->assertSendable();
        $logger = $this->logger ?? new NullLogger();

        $mail = $this->createPhpMailer();
        try {
            // Default to PHP mail(); the configurator may switch to isSMTP() etc.
            $mail->isMail();
            if ($this->configurator !== null) {
                ($this->configurator)($mail);
            }

            // Envelope sender: fixed validated address, explicitly pinned so
            // setFrom() auto-population can never introduce another value.
            if ($this->envelopeSender !== null) {
                $mail->Sender = $this->envelopeSender->address;
            }

            $from = $message->getFrom();
            $mail->setFrom($from->address, $from->displayName ?? '');

            if ($message->getSender() !== null) {
                $mail->Sender = $message->getSender()->address;
            }
            if ($message->getReplyTo() !== null) {
                $mail->addReplyTo(
                    $message->getReplyTo()->address,
                    $message->getReplyTo()->displayName ?? '',
                );
            }

            foreach ($message->getTo() as $r) {
                $mail->addAddress($r->address, $r->displayName ?? '');
            }
            foreach ($message->getCc() as $r) {
                $mail->addCC($r->address, $r->displayName ?? '');
            }
            foreach ($message->getBcc() as $r) {
                $mail->addBCC($r->address, $r->displayName ?? '');
            }

            // PHPMailer encodes the subject itself, but we pass a value that
            // is already guaranteed CR/LF-free.
            $mail->Subject = $message->getSubject();
            $mail->isHTML($message->getHtmlBody() !== '');
            if ($message->getTextBody() !== '') {
                $mail->Body = $message->getTextBody();
                $mail->AltBody = '';
                if ($message->getHtmlBody() !== '') {
                    $mail->isHTML(true);
                    $mail->Body = $message->getHtmlBody();
                    $mail->AltBody = $message->getTextBody();
                }
            } else {
                $mail->Body = $message->getHtmlBody();
            }

            // Custom headers come from HeaderSet, already validated/encoded.
            foreach ($message->getCustomHeaders()->all() as $h) {
                $mail->addCustomHeader($h['name'], $h['value']);
            }

            $logger->info('PhpMailerMailer::send', [
                'to' => array_map(static fn(EmailAddress $a): string => $a->address, $message->getTo()),
            ]);

            $mail->send();
        } catch (PHPMailerException $e) {
            throw new MailerException('PHPMailer failure: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * Construction seam: tests can override to inject a PHPMailer subclass
     * whose transport methods are stubbed, keeping production code on `new`.
     */
    protected function createPhpMailer(): PHPMailer
    {
        return new PHPMailer(true);
    }
}
