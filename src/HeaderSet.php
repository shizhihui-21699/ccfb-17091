<?php

declare(strict_types=1);

namespace MailGuard;

/**
 * Holds validated custom headers. Headers that are managed by the Message
 * itself (Subject, To, Cc, Bcc, From, Sender, Reply-To, Date, Message-ID,
 * MIME-Version, Content-Type, Content-Transfer-Encoding) cannot be set here.
 */
final class HeaderSet
{
    private const RESERVED = [
        'subject', 'to', 'cc', 'bcc', 'from', 'sender', 'reply-to',
        'date', 'message-id', 'mime-version', 'content-type',
        'content-transfer-encoding', 'content-disposition',
        'return-path', 'received', 'dkim-signature',
    ];

    /** @var list<array{name:string, value:string}> */
    private array $headers = [];

    public function add(string $name, string $value): void
    {
        $name = MimeHeader::validateFieldName($name);
        $lower = strtolower($name);
        if (in_array($lower, self::RESERVED, true)) {
            throw new MailerException(sprintf('Header "%s" is managed by the mailer and cannot be overridden', $name));
        }
        // Values go through the unstructured validator: no CR/LF, no controls.
        $encoded = MimeHeader::encodeUnstructured($value, $name);
        $this->headers[] = ['name' => $name, 'value' => $encoded];
    }

    /** @return list<array{name:string, value:string}> */
    public function all(): array
    {
        return $this->headers;
    }

    /**
     * Render as RFC 5322 "Name: value" lines (without trailing CRLF — the
     * transport adds the terminator).
     *
     * @return list<string>
     */
    public function renderLines(): array
    {
        return array_map(
            static fn(array $h): string => $h['name'] . ': ' . $h['value'],
            $this->headers,
        );
    }
}
