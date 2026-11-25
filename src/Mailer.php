<?php

declare(strict_types=1);

namespace MailGuard;

interface Mailer
{
    /**
     * @throws ValidationException when a field fails validation
     * @throws MailerException when transport policy is violated or sending fails
     */
    public function send(Message $message): void;
}
