<?php

declare(strict_types=1);

namespace MailGuard\Scanner;

/**
 * Renders Finding lists as human-readable text or machine-readable JSON.
 */
final class Report
{
    /**
     * @param list<Finding> $findings
     */
    public static function text(array $findings): string
    {
        if ($findings === []) {
            return "No mail-related sinks found.\n";
        }

        $counts = [Finding::SEVERITY_CRITICAL => 0, Finding::SEVERITY_WARNING => 0, Finding::SEVERITY_INFO => 0];
        $out = '';
        foreach ($findings as $f) {
            $counts[$f->severity]++;
            $tag = strtoupper($f->severity);
            $out .= sprintf(
                "[%s] %s:%d  %s\n    %s\n    > %s\n\n",
                $tag,
                $f->file,
                $f->line,
                $f->sink,
                $f->message,
                $f->snippet,
            );
        }

        $out .= sprintf(
            "Summary: %d critical, %d warning, %d info (%d total)\n",
            $counts[Finding::SEVERITY_CRITICAL],
            $counts[Finding::SEVERITY_WARNING],
            $counts[Finding::SEVERITY_INFO],
            count($findings),
        );
        return $out;
    }

    /**
     * @param list<Finding> $findings
     */
    public static function json(array $findings): string
    {
        return json_encode(
            array_map(static fn(Finding $f): array => $f->toArray(), $findings),
            JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE,
        ) . "\n";
    }
}
