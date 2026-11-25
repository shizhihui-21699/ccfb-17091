<?php

declare(strict_types=1);

namespace MailGuard;

/**
 * Builds MIME body parts and content headers for a Message.
 * Bodies are attacker-influenced (e.g. password-reset links containing a
 * token), so transfer encoding is always applied: 7-bit-safe text stays
 * quoted-printable, anything else base64 — raw CR/LF inside a body can never
 * terminate headers because the body is never parsed as headers.
 */
final class MimeBody
{
    public static function boundary(): string
    {
        return '=_MailGuard_' . bin2hex(random_bytes(16));
    }

    /**
     * @return array{headers: list<string>, body: string}
     */
    public static function compose(Message $message): array
    {
        $hasText = $message->getTextBody() !== '';
        $hasHtml = $message->getHtmlBody() !== '';

        if ($hasText && !$hasHtml) {
            return self::singlePart($message->getTextBody(), 'text/plain; charset=UTF-8');
        }
        if ($hasHtml && !$hasText) {
            return self::singlePart($message->getHtmlBody(), 'text/html; charset=UTF-8');
        }

        // multipart/alternative
        $boundary = self::boundary();
        $headers = ['Content-Type: multipart/alternative; boundary="' . $boundary . '"'];
        $body = '';
        $body .= '--' . $boundary . "\r\n";
        $text = self::singlePart($message->getTextBody(), 'text/plain; charset=UTF-8');
        $body .= implode("\r\n", $text['headers']) . "\r\n\r\n" . $text['body'] . "\r\n";
        $body .= '--' . $boundary . "\r\n";
        $html = self::singlePart($message->getHtmlBody(), 'text/html; charset=UTF-8');
        $body .= implode("\r\n", $html['headers']) . "\r\n\r\n" . $html['body'] . "\r\n";
        $body .= '--' . $boundary . "--\r\n";

        return ['headers' => $headers, 'body' => $body];
    }

    /**
     * @return array{headers: list<string>, body: string}
     */
    private static function singlePart(string $content, string $contentType): array
    {
        if (self::isAsciiSafe($content)) {
            // Quoted-printable keeps the part mostly readable while neutralising
            // bare line endings and any stray high-bit bytes.
            $encoded = quoted_printable_encode(
                // Normalise CRLF/CR -> LF first so QP encoding is canonical.
                str_replace(["\r\n", "\r"], "\n", $content),
            );
            return [
                'headers' => [
                    'Content-Type: ' . $contentType,
                    'Content-Transfer-Encoding: quoted-printable',
                ],
                'body' => $encoded,
            ];
        }

        return [
            'headers' => [
                'Content-Type: ' . $contentType,
                'Content-Transfer-Encoding: base64',
            ],
            'body' => chunk_split(base64_encode($content)),
        ];
    }

    private static function isAsciiSafe(string $s): bool
    {
        return preg_match('//u', $s) === 1 && preg_match('/[^\x09\x0A\x0D\x20-\x7E]/', $s) !== 1;
    }
}
