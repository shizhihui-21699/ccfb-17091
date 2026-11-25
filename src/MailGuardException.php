<?php

declare(strict_types=1);

namespace MailGuard;

/**
 * Base class for every MailGuard failure. Callers can catch this one type
 * to reject the whole mail operation safely.
 */
class MailGuardException extends \RuntimeException
{
}
