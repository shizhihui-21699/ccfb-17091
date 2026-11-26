<?php

declare(strict_types=1);

namespace MailGuard;

/**
 * Hardened adapter for WordPress' wp_mail() pluggable function.
 *
 * Background: wp_mail($to, $subject, $message, $headers, $attachments) has
 * historically been a header-injection sink when $to or $headers were built
 * from unsanitised request data (WordPress core added wp_mail argument
 * sanitisation in 5.0.x, but plugins frequently pre-format "Name <addr>"
 * strings and raw headers themselves).
 *
 * This adapter:
 *  - passes recipients as validated ASCII addresses (display names move into
 *    properly formatted header lines, never into the $to array raw)
 *  - renders every header through MimeHeader so CR/LF cannot survive
 *  - NEVER passes anything derived from request input into the underlying
 *    PHPMailer Sender / -f parameter. The envelope sender is a fixed config
 *    value enforced via the phpmailer_init action.
 *  - restores any filters it registers
 */
final class WordPressMailer implements Mailer
{
    private bool $functionsExist;

    /**
     * @param EmailAddress|null $envelopeSender Fixed envelope sender from site config.
     */
    public function __construct(
        private readonly ?EmailAddress $envelopeSender = null,
        private readonly ?MailLogger $logger = null,
    ) {
        $this->functionsExist = function_exists('wp_mail') && function_exists('add_filter') && function_exists('add_action');
    }

    public function send(Message $message): void
    {
        $message->assertSendable();

        if (!$this->functionsExist) {
            throw new MailerException('WordPress runtime (wp_mail) is not available in this SAPI');
        }

        $logger = $this->logger ?? new NullLogger();

        // 1. Recipients: plain validated addresses only.
        $to = array_map(
            static fn(EmailAddress $a): string => $a->address,
            $message->getTo(),
        );

        // 2. Headers rendered by us from validated data.
        $headers = [];
        $from = $message->getFrom();
        $headers[] = 'From: ' . MimeHeader::formatMailbox($from);
        if ($message->getReplyTo() !== null) {
            $headers[] = 'Reply-To: ' . MimeHeader::formatMailbox($message->getReplyTo());
        }
        if ($message->getCc() !== []) {
            $headers[] = 'Cc: ' . MimeHeader::formatMailboxList($message->getCc());
        }
        if ($message->getBcc() !== []) {
            $headers[] = 'Bcc: ' . MimeHeader::formatMailboxList($message->getBcc());
        }
        foreach ($message->getCustomHeaders()->renderLines() as $line) {
            $headers[] = $line;
        }

        // 3. Content type: prefer HTML when present, with alt text where both.
        $contentType = $message->getHtmlBody() !== '' ? 'text/html' : 'text/plain';
        $contentTypeCallback = static fn(): string => $contentType;
        $filterRegistered = false;
        if (function_exists('add_filter')) {
            add_filter('wp_mail_content_type', $contentTypeCallback);
            $filterRegistered = true;
        }

        // 4. Pin the envelope sender via phpmailer_init, overriding anything
        //    another plugin might have set. This is the ONLY place Sender is
        //    touched and its value is application config, not request data.
        $senderPinned = false;
        if ($this->envelopeSender !== null && function_exists('add_action')) {
            $fixedSender = $this->envelopeSender->address;
            add_action('phpmailer_init', static function ($phpmailer) use ($fixedSender): void {
                $phpmailer->Sender = $fixedSender;
            });
            $senderPinned = true;
        }

        $body = $message->getHtmlBody() !== '' ? $message->getHtmlBody() : $message->getTextBody();

        $logger->info('WordPressMailer::send', [
            'to' => $to,
            'envelopeSenderPinned' => $senderPinned,
        ]);

        $ok = wp_mail($to, $message->getSubject(), $body, $headers);

        if ($filterRegistered && function_exists('remove_filter')) {
            remove_filter('wp_mail_content_type', $contentTypeCallback);
        }

        if (!$ok) {
            throw new MailerException('wp_mail() reported failure');
        }
    }
}
