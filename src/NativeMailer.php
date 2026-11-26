<?php

declare(strict_types=1);

namespace MailGuard;

/**
 * Hardened wrapper around PHP's native mail() function.
 *
 * Threats addressed (CWE-88 argument injection, CWE-93/CRLF header injection):
 *
 *  1. $to, $subject and every header are derived exclusively from validated
 *     value objects — user strings never reach mail() directly.
 *  2. The fifth argument ($additional_parameters) is NEVER populated from
 *     request data. The only supported flag is the envelope sender (-f),
 *     taken from a pre-validated EmailAddress configured by the application.
 *     No concatenation, no escapeshellarg of user input, no other flags.
 *  3. On Windows, where -f handling differs and escapeshellarg semantics are
 *     inverted, additional parameters are not emitted at all.
 *  4. The subject is RFC 2047 encoded by us; even historically-broken PHP
 *     builds that allowed newlines in subjects cannot receive one.
 *
 * The constructor takes an optional callable so tests can stub mail() and
 * production code can keep using the real built-in.
 */
final class NativeMailer implements Mailer
{
    /**
     * @param EmailAddress|null $envelopeSender Pre-validated fixed sender for -f (never user input).
     * @param MailLogger|null   $logger
     * @param callable|null     $mailFn         function(string $to,string $subj,string $body,string $headers,?string $params):bool
     */
    public function __construct(
        private readonly ?EmailAddress $envelopeSender = null,
        private readonly ?MailLogger $logger = null,
        private readonly mixed $mailFn = null,
    ) {
    }

    public function send(Message $message): void
    {
        $message->assertSendable();
        $logger = $this->logger ?? new NullLogger();

        $useUnicode = false; // native mail()/sendmail has no SMTPUTF8 negotiation
        $headerLines = $this->buildHeaders($message, $useUnicode);
        $mime = MimeBody::compose($message);
        $headerLines = array_merge($headerLines, $mime['headers']);

        $to = $this->buildEnvelopeRecipients($message);
        $subject = MimeHeader::encodeUnstructured($message->getSubject(), 'subject');
        $headersString = implode("\r\n", $headerLines);

        // Final belt-and-braces scan: nothing we emit may contain a raw NUL,
        // and no header line may contain a lone CR or LF inside its value.
        $this->assertNoInjection($to, $subject, $headersString);

        $params = $this->buildAdditionalParameters($logger);

        $fn = $this->mailFn ?? 'mail';
        $logger->info('NativeMailer::send', [
            'to' => array_map(static fn(EmailAddress $a): string => $a->address, $this->allRecipients($message)),
            'from' => $message->getFrom()?->address,
            'hasAdditionalParams' => $params !== null,
        ]);

        $ok = $fn($to, $subject, $mime['body'], $headersString, $params);
        if ($ok !== true) {
            throw new MailerException('mail() transport reported failure');
        }
    }

    /**
     * @return list<string>
     */
    private function buildHeaders(Message $message, bool $unicode): array
    {
        $lines = [];
        $lines[] = 'Date: ' . date('r');
        $lines[] = 'MIME-Version: 1.0';
        $lines[] = 'From: ' . MimeHeader::formatMailbox($message->getFrom(), $unicode);

        if ($message->getSender() !== null) {
            $lines[] = 'Sender: ' . MimeHeader::formatMailbox($message->getSender(), $unicode);
        }
        if ($message->getReplyTo() !== null) {
            $lines[] = 'Reply-To: ' . MimeHeader::formatMailbox($message->getReplyTo(), $unicode);
        }
        if ($message->getTo() !== []) {
            $lines[] = 'To: ' . MimeHeader::formatMailboxList($message->getTo(), $unicode);
        }
        if ($message->getCc() !== []) {
            $lines[] = 'Cc: ' . MimeHeader::formatMailboxList($message->getCc(), $unicode);
        }
        if ($message->getBcc() !== []) {
            // sendmail itself strips Bcc before delivery; the addresses are
            // still passed as envelope recipients via $to.
            $lines[] = 'Bcc: ' . MimeHeader::formatMailboxList($message->getBcc(), $unicode);
        }

        foreach ($message->getCustomHeaders()->all() as $h) {
            $lines[] = $h['name'] . ': ' . $h['value'];
        }

        return $lines;
    }

    private function buildEnvelopeRecipients(Message $message): string
    {
        // Plain addresses only (no display name) — every entry is a validated
        // ASCII addr-spec, joined with the RFC separator.
        return implode(', ', array_map(
            static fn(EmailAddress $a): string => $a->address,
            $this->allRecipients($message),
        ));
    }

    /**
     * @return list<EmailAddress>
     */
    private function allRecipients(Message $message): array
    {
        return array_merge($message->getTo(), $message->getCc(), $message->getBcc());
    }

    /**
     * The ONLY sanctioned use of mail()'s fifth parameter. The value is a
     * fixed, application-configured, already-validated address — there is no
     * code path through which request data reaches this string.
     */
    private function buildAdditionalParameters(MailLogger $logger): ?string
    {
        if ($this->envelopeSender === null) {
            return null;
        }

        if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
            // Windows PHP builds its own Sendmail command line and handle -f
            // via php.ini; emitting extra params risks quoting inversion.
            $logger->warning('Additional -f parameter skipped on Windows; configure sendmail_from in php.ini');
            return null;
        }

        // The address is validated and ASCII A-label form by construction.
        // Re-assert the invariant locally anyway.
        $address = $this->envelopeSender->address;
        if (preg_match('/^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+$/', $address) !== 1) {
            throw new MailerException('Envelope sender is not a plain ASCII addr-spec; refusing -f parameter');
        }

        return '-f' . $address;
    }

    /**
     * Last line of defence: prove the rendered fields carry no CR/LF/NUL
     * outside the CRLF separators we ourselves inserted between header lines.
     */
    private function assertNoInjection(string $to, string $subject, string $headers): void
    {
        foreach (['to' => $to, 'subject' => $subject] as $field => $value) {
            if (preg_match('/[\x00\r\n]/', $value)) {
                throw new MailerException("Rendered {$field} unexpectedly contained CR/LF/NUL");
            }
        }

        foreach (explode("\r\n", $headers) as $line) {
            if ($line === '') {
                continue; // legitimate separator
            }
            // A folded continuation line begins with a space (our own folding).
            // Any OTHER CR, LF or NUL means an injection survived validation.
            if (preg_match('/[\x00\r]/', $line) || (str_contains($line, "\n"))) {
                throw new MailerException('Rendered header block contained an illegal line break');
            }
        }
    }
}
