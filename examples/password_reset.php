<?php

declare(strict_types=1);

/**
 * Reference implementation for a password-reset endpoint.
 *
 * Two controllers are shown side by side:
 *   - VulnerableResetController   — the vulnerable pattern from the incident
 *   - HardenedResetController     — the MailGuard-based replacement
 *
 * The HTTP layer here is a tiny fake so the file runs standalone:
 *   php examples/password_reset.php
 */

require __DIR__ . '/../vendor/autoload.php';

use MailGuard\EmailAddress;
use MailGuard\MailGuard;
use MailGuard\MailerException;
use MailGuard\NativeMailer;
use MailGuard\ValidationException;
use MailGuard\ValidationOptions;

/* ----------------------------------------------------------------- *
 * Shared fake infrastructure (request + recording mail transport)
 * ----------------------------------------------------------------- */

final class FakeRequest
{
    /** @param array<string,string> $post */
    public function __construct(private array $post)
    {
    }

    public function post(string $key): ?string
    {
        return $this->post[$key] ?? null;
    }
}

final class Recorder
{
    /** @var list<array{to:string,subject:string,body:string,headers:string,params:?string}> */
    public array $calls = [];

    public function mail(string $to, string $subject, string $body, string $headers, ?string $params): bool
    {
        $this->calls[] = compact('to', 'subject', 'body', 'headers', 'params');
        return true;
    }
}

/* ----------------------------------------------------------------- *
 * BEFORE: vulnerable controller (DO NOT USE — documented for audit)
 * ----------------------------------------------------------------- */

final class VulnerableResetController
{
    public function __construct(private Recorder $mail)
    {
    }

    public function __invoke(FakeRequest $request): string
    {
        $email = $request->post('email');

        // VULN 1: raw user value into $to — CRLF injection possible.
        // VULN 2: hand-built headers with literal \r\n.
        // VULN 3: fifth parameter built from request data — -X webshell possible.
        $headers = "From: noreply@example.com\r\n";
        $sender = $request->post('sender') ?? 'www-data';
        $this->mail->mail($email, 'Password reset', 'token', $headers, '-f' . $sender);

        return "vulnerable: accepted {$email}";
    }
}

/* ----------------------------------------------------------------- *
 * AFTER: hardened controller
 * ----------------------------------------------------------------- */

final class HardenedResetController
{
    public function __construct(private Recorder $mail)
    {
        // Configure MailGuard once per application bootstrap.
        if (MailGuard::class !== null) {
            MailGuard::setDefaultFrom(EmailAddress::fromUserInput('noreply@example.com', 'Example'));
            // Envelope sender is FIXED application config, never request data.
            MailGuard::setDefaultMailer(new NativeMailer(
                EmailAddress::fromUserInput('bounces@example.com'),
                null,
                $this->mail->mail(...),
            ));
        }
    }

    public function __invoke(FakeRequest $request): string
    {
        $raw = (string)$request->post('email');

        // Single choke point: every user-supplied address is validated here.
        try {
            $recipient = EmailAddress::fromUserInput($raw, null, ValidationOptions::default());
        } catch (ValidationException $e) {
            // Generic user-facing message; details go to security logs only.
            error_log('[security] rejected reset email: ' . $e->getMessage());
            return 'hardened: rejected (invalid email format)';
        }

        try {
            MailGuard::mailer()->send(
                MailGuard::newMessage('Password reset')
                    ->to($recipient)
                    ->text('Your reset token: 3f8a-…')
                    ->addHeader('X-Request-Id', bin2hex(random_bytes(8))),
            );
        } catch (MailerException $e) {
            error_log('[mail] transport failure: ' . $e->getMessage());
            return 'hardened: temporary mail failure, please retry';
        }

        return "hardened: accepted {$recipient->address}";
    }
}

/* ----------------------------------------------------------------- *
 * Demo
 * ----------------------------------------------------------------- */

$attack = new FakeRequest([
    'email' => "victim@example.com\r\nBcc: spam@evil.example",
    'sender' => 'www -oQ/tmp -X/var/www/html/shell.php',
]);
// IDN domain with an ASCII local part: works on every legacy transport,
// because only the domain needs puny-coding.
$normalIdn = new FakeRequest(['email' => 'tanaka@例え.jp']);
$normalAscii = new FakeRequest(['email' => 'jane.doe@example.co.uk']);

echo "--- Vulnerable controller (shows why the incident was possible) ---\n";
$vuln = new VulnerableResetController(new Recorder());
echo $vuln($attack), "\n";
echo "  => injection accepted; sendmail would receive -X pointing at the web root\n\n";

echo "--- Hardened controller ---\n";
$recorder = new Recorder();
$hardened = new HardenedResetController($recorder);
echo $hardened($attack), "\n";
echo $hardened($normalIdn), "  (transported as: {$recorder->calls[0]['to']})\n";
echo $hardened($normalAscii), "\n";
