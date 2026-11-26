<?php

declare(strict_types=1);

namespace MailGuardTests;

use MailGuard\EmailAddress;
use MailGuard\Message;
use MailGuard\NativeMailer;
use MailGuard\ValidationException;
use MailGuard\ValidationOptions;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Regression suite for the actual incident, encoded as CI-gated tests rather
 * than only the standalone bin/attack_poc script.
 *
 * Incident chain:
 *   1. CRLF / encoded-newline in the address field injects Bcc recipients and
 *      a new body (CWE-93 header injection).
 *   2. sendmail additional parameters (-X log path, -oQ queue dir) are abused
 *      to drop an executable "log" under the web root (CWE-88 argument
 *      injection). The fix removes every user-controlled path to the fifth
 *      mail() argument and pins -f to a fixed, validated config address.
 *
 * The companion requirement — legitimate international mail still flows — is
 * asserted here too, so the hardening can never silently regress into blocking
 * real users.
 */
final class IncidentChainTest extends TestCase
{
    /** @var list<array{to:string,subject:string,body:string,headers:string,params:?string}> */
    private array $captured = [];

    private function recordingMailer(?EmailAddress $envelope = null): NativeMailer
    {
        $this->captured = [];
        $fn = function (string $to, string $subject, string $body, string $headers, ?string $params): bool {
            $this->captured[] = compact('to', 'subject', 'body', 'headers', 'params');
            return true;
        };
        return new NativeMailer($envelope, null, $fn);
    }

    /**
     * Every shape the attacker used to smuggle a line break must be rejected
     * at the single validation choke point, before any transport is touched.
     */
    #[DataProvider('headerInjectionPayloads')]
    public function testCrlfInjectionIsRejectedAtValidationBoundary(string $payload): void
    {
        $this->expectException(ValidationException::class);
        EmailAddress::fromUserInput($payload);
    }

    /**
     * @return array<string, array{0:string}>
     */
    public static function headerInjectionPayloads(): array
    {
        return [
            'crlf + bcc recipients' => ["victim@example.com\r\nBcc: spam1@evil.example,spam2@evil.example"],
            'lf only' => ["victim@example.com\nBcc: spam@evil.example"],
            'cr only' => ["victim@example.com\rBcc: spam@evil.example"],
            'crlf then body' => ["victim@example.com\r\n\r\n<script>steal()</script>"],
            'via angle-addr display name' => ["Attacker <x@example.com>\r\nBcc: spam@evil.example"],
            'url-encoded newlines' => ["x@example.com%0d%0aBcc:%20spam@evil.example"],
            'nul byte' => ["x\x00@example.com"],
            'newline inside local part' => ["x\n@example.com"],
        ];
    }

    #[DataProvider('sendmailParameterPayloads')]
    public function testSendmailParameterPayloadsAreNotValidAddresses(string $payload): void
    {
        $this->expectException(ValidationException::class);
        EmailAddress::fromUserInput($payload);
    }

    /**
     * @return array<string, array{0:string}>
     */
    public static function sendmailParameterPayloads(): array
    {
        return [
            'log-to-webshell with -f' => ['-X/var/www/html/shell.php -fwww@victim'],
            'queue dir + log path' => ['attacker@x -oQ/tmp -X/var/www/html/shell.php'],
        ];
    }

    public function testFlagLookingButValidLocalPartCannotReachCommandLine(): void
    {
        // A local part may legitimately start with a hyphen ("-" is RFC atext),
        // so the address validator correctly ACCEPTS it — the defence against
        // sendmail -f/-r/-X injection must therefore live in NativeMailer never
        // feeding request data into the fifth argument, not in address syntax.
        // Prove the boundary: such a recipient stays in $to and cannot influence
        // $additional_parameters.
        $flagLike = EmailAddress::fromUserInput('-rattacker@example.com');
        self::assertSame('-rattacker@example.com', $flagLike->address);

        $mailer = $this->recordingMailer(EmailAddress::fromUserInput('bounces@example.com'));
        $mailer->send(
            Message::create()
                ->from(EmailAddress::fromUserInput('noreply@example.com'))
                ->to($flagLike)
                ->subject('Notice')
                ->text('Body'),
        );

        self::assertSame('-rattacker@example.com', $this->captured[0]['to']);
        // The only command-line parameter remains the fixed config -f sender;
        // the recipient's hyphen prefix never becomes a sendmail switch.
        self::assertSame('-fbounces@example.com', $this->captured[0]['params']);
    }

    public function testOnlyFixedEnvelopeSenderEverReachesAdditionalParameters(): void
    {
        $envelope = EmailAddress::fromUserInput('bounces@example.com');
        $mailer = $this->recordingMailer($envelope);

        $mailer->send(
            Message::create()
                ->from(EmailAddress::fromUserInput('noreply@example.com'))
                ->to(EmailAddress::fromUserInput('real-user@example.com'))
                ->subject('Password reset')
                ->text('Reset link: https://example.com/reset?token=secret'),
        );

        self::assertCount(1, $this->captured);
        $params = $this->captured[0]['params'];

        // The single sanctioned flag is the fixed -f config sender — nothing
        // derived from the request can reach this string.
        self::assertSame('-fbounces@example.com', $params);
        self::assertStringNotContainsString('-X', (string) $params);
        self::assertStringNotContainsString('-oQ', (string) $params);
        self::assertStringNotContainsString('-r', (string) $params);
    }

    public function testNoAdditionalParameterWithoutConfiguredEnvelopeSender(): void
    {
        $mailer = $this->recordingMailer(null);

        $mailer->send(
            Message::create()
                ->from(EmailAddress::fromUserInput('noreply@example.com'))
                ->to(EmailAddress::fromUserInput('user@example.com'))
                ->subject('Notice')
                ->text('Hello'),
        );

        // With no fixed envelope sender the fifth argument is omitted entirely,
        // so there is no command-line surface for an attacker to reach.
        self::assertNull($this->captured[0]['params']);
    }

    public function testInjectedBccNeverAppearsInRenderedHeaders(): void
    {
        // The attacker-controlled value never even becomes an EmailAddress, but
        // assert the rendered output of a legitimate message carries no trace
        // of an attacker domain even when an unrelated body mentions one.
        $mailer = $this->recordingMailer(EmailAddress::fromUserInput('bounces@example.com'));

        $mailer->send(
            Message::create()
                ->from(EmailAddress::fromUserInput('noreply@example.com'))
                ->to(EmailAddress::fromUserInput('real-user@example.com'))
                ->subject('Reset')
                ->text("If you did not request this, contact support@evil.example."),
        );

        $headers = $this->captured[0]['headers'];
        self::assertStringNotContainsString('Bcc:', $headers);
        // A domain mentioned in the (transfer-encoded) body cannot surface as
        // an envelope recipient.
        self::assertSame('real-user@example.com', $this->captured[0]['to']);
    }

    public function testLegitimateInternationalMailStillDeliversAfterHardening(): void
    {
        $mailer = $this->recordingMailer(EmailAddress::fromUserInput('bounces@example.com'));

        // IDN domain: must be puny-coded on the transport without the user
        // entering punycode, and a Unicode subject must be MIME-encoded.
        $mailer->send(
            Message::create()
                ->from(EmailAddress::fromUserInput('noreply@example.com', '我的站点'))
                ->to(EmailAddress::fromUserInput('user@例え.jp', 'ユーザー'))
                ->subject('重置密码')
                ->html('<p>点击重置</p>')
                ->text('点击重置'),
        );

        $call = $this->captured[0];
        self::assertSame('user@xn--r8jz45g.jp', $call['to']);
        self::assertStringStartsWith('=?UTF-8?B?', $call['subject']);
        // No raw line break can survive into the encoded subject/headers.
        self::assertDoesNotMatchRegularExpression('/[^\r]\n/', $call['headers']);
    }

    public function testUnicodeLocalPartOptInStillWorksForSmtputf8Transport(): void
    {
        // Default policy rejects Unicode local parts (legacy sendmail has no
        // SMTPUTF8); an explicit SMTPUTF8-capable opt-in must still accept it,
        // proving the policy switch works and real users are not blocked.
        $options = (new ValidationOptions())->withUnicodeLocalPart(true);
        $address = EmailAddress::fromUserInput('用户@example.com', null, $options);
        self::assertStringEndsWith('@example.com', $address->address);

        $this->expectException(ValidationException::class);
        EmailAddress::fromUserInput('用户@example.com');
    }
}
