<?php

declare(strict_types=1);

namespace MailGuard;

/**
 * Single entry point for application code. Typical password-reset flow:
 *
 *   MailGuard::mailer()->send(
 *       MailGuard::newMessage('Reset your password')
 *           ->to(MailGuard::address($_POST['email']))
 *           ->from(MailGuard::address('noreply@example.com', 'Example'))
 *           ->text($resetBody)
 *   );
 *
 * Every user-supplied value MUST pass through MailGuard::address(); raw
 * strings are never accepted by the Message/mailer layer.
 */
final class MailGuard
{
    private static ?Mailer $defaultMailer = null;
    private static ?EmailAddress $defaultFrom = null;
    private static ?ValidationOptions $validationOptions = null;

    public static function setDefaultMailer(Mailer $mailer): void
    {
        self::$defaultMailer = $mailer;
    }

    public static function setDefaultFrom(EmailAddress $from): void
    {
        self::$defaultFrom = $from;
    }

    public static function setValidationOptions(ValidationOptions $options): void
    {
        self::$validationOptions = $options;
    }

    /**
     * Validate a user-supplied address (optionally with display name).
     *
     * @throws ValidationException on any control character, malformed address
     *                             or policy violation
     */
    public static function address(string $address, ?string $displayName = null): EmailAddress
    {
        return EmailAddress::fromUserInput($address, $displayName, self::$validationOptions);
    }

    public static function newMessage(string $subject): Message
    {
        $message = new Message();
        $message->subject($subject);
        if (self::$defaultFrom !== null) {
            $message->from(self::$defaultFrom);
        }
        return $message;
    }

    public static function mailer(): Mailer
    {
        if (self::$defaultMailer === null) {
            throw new MailerException('No default mailer configured; call MailGuard::setDefaultMailer() first');
        }
        return self::$defaultMailer;
    }

    /** Test support: reset all static state. */
    public static function reset(): void
    {
        self::$defaultMailer = null;
        self::$defaultFrom = null;
        self::$validationOptions = null;
    }
}
