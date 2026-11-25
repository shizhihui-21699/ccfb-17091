<?php

declare(strict_types=1);

namespace MailGuard;

/**
 * Minimal structured logger so security events (rejected input, actual
 * send attempts) can be routed into the site's existing logging without
 * taking a PSR dependency.
 */
interface MailLogger
{
    public function info(string $message, array $context = []): void;
    public function warning(string $message, array $context = []): void;
    public function error(string $message, array $context = []): void;
}
