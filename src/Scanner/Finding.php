<?php

declare(strict_types=1);

namespace MailGuard\Scanner;

/**
 * One finding produced by SinkScanner.
 */
final class Finding
{
    public const SEVERITY_CRITICAL = 'critical';
    public const SEVERITY_WARNING = 'warning';
    public const SEVERITY_INFO = 'info';

    public function __construct(
        public readonly string $file,
        public readonly int $line,
        public readonly string $severity,
        public readonly string $sink,
        public readonly string $message,
        public readonly string $snippet,
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'file' => $this->file,
            'line' => $this->line,
            'severity' => $this->severity,
            'sink' => $this->sink,
            'message' => $this->message,
            'snippet' => $this->snippet,
        ];
    }
}
