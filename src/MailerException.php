<?php

declare(strict_types=1);

namespace MailGuard;

/**
 * Thrown when a mailer is asked to do something that the hardening policy
 * forbids (e.g. pass arbitrary content into mail()'s $additional_parameters).
 */
class MailerException extends MailGuardException
{
}
