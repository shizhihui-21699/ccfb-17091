<?php

declare(strict_types=1);

namespace MailGuardTests;

use MailGuard\Scanner\Finding;
use MailGuard\Scanner\SinkScanner;
use PHPUnit\Framework\TestCase;

final class SinkScannerTest extends TestCase
{
    private string $fixture;

    protected function setUp(): void
    {
        $this->fixture = __DIR__ . '/fixtures/vulnerable_site.php';
    }

    public function testFindsNativeMailWithFifthParameter(): void
    {
        $findings = (new SinkScanner())->scanFile($this->fixture);
        $criticals = array_filter(
            $findings,
            static fn(Finding $f): bool => $f->sink === 'mail():additional_parameters',
        );
        self::assertNotEmpty($criticals);
        self::assertSame(Finding::SEVERITY_CRITICAL, $criticals[array_key_first($criticals)]->severity);
    }

    public function testFindsSuperglobalFlowingIntoMailSinks(): void
    {
        $findings = (new SinkScanner())->scanFile($this->fixture);
        $superglobalFindings = array_filter(
            $findings,
            static fn(Finding $f): bool => str_contains($f->message, 'superglobal'),
        );
        // mail($_GET 5th arg), wp_mail($_REQUEST + $_POST in headers),
        // PHPMailer setFrom($_POST), addCustomHeader($_POST), Swift setTo($_POST)
        self::assertGreaterThanOrEqual(5, count($superglobalFindings));
        foreach ($superglobalFindings as $f) {
            self::assertSame(Finding::SEVERITY_CRITICAL, $f->severity);
        }
    }

    public function testFindsSendmailFlagConcatenation(): void
    {
        $findings = (new SinkScanner())->scanFile($this->fixture);
        $flags = array_filter(
            $findings,
            static fn(Finding $f): bool => $f->sink === 'mail():sendmail-flag',
        );
        self::assertNotEmpty($flags);
    }

    public function testFindsCrlfHeaderStringBuilding(): void
    {
        $findings = (new SinkScanner())->scanFile($this->fixture);
        $crlf = array_filter(
            $findings,
            static fn(Finding $f): bool => $f->sink === 'mail():crlf-literal'
                || str_contains($f->message, 'CR/LF')
                || str_contains($f->message, 'CRLF'),
        );
        self::assertNotEmpty($crlf);
    }

    public function testFindsLibraryConstructsAndSendCalls(): void
    {
        $findings = (new SinkScanner())->scanFile($this->fixture);
        $sinks = array_map(static fn(Finding $f): string => $f->sink, $findings);
        self::assertContains('construct:PHPMailer', $sinks);
        self::assertContains('construct:Swift_Message', $sinks);
        self::assertContains('construct:Swift_SendmailTransport', $sinks);
        self::assertContains('method::send', $sinks);
        self::assertContains('PHPMailer::setFrom', $sinks);
        self::assertContains('Swift_Message::setTo', $sinks);
        self::assertContains('Symfony Email::to', $sinks);
    }

    public function testFindsWpMailCall(): void
    {
        $findings = (new SinkScanner())->scanFile($this->fixture);
        $wp = array_filter($findings, static fn(Finding $f): bool => str_starts_with($f->sink, 'wp_mail'));
        self::assertNotEmpty($wp);
    }

    public function testFindingsAreSortedCriticalFirstAndHaveLineNumbers(): void
    {
        $findings = (new SinkScanner())->scanFile($this->fixture);
        self::assertNotEmpty($findings);
        $rank = [Finding::SEVERITY_CRITICAL => 0, Finding::SEVERITY_WARNING => 1, Finding::SEVERITY_INFO => 2];
        $previous = -1;
        foreach ($findings as $f) {
            // Severities must never regress (critical block, then warning, then info).
            self::assertGreaterThanOrEqual($previous, $rank[$f->severity]);
            $previous = $rank[$f->severity];
            self::assertGreaterThan(0, $f->line);
            self::assertNotSame('', $f->snippet);
        }    }

    public function testIgnoresCommentsAndFunctionDefinitions(): void
    {
        $tmp = tempnam(sys_get_temp_dir(), 'mg') . '.php';
        file_put_contents($tmp, '<?php
        // mail("commented@example.com");
        function mail_wrapper($to) { return; }
        $x = "wp_mail is mentioned in a string";
        ');
        $findings = (new SinkScanner())->scanFile($tmp);
        self::assertSame([], $findings);
        unlink($tmp);
    }

    public function testDirectoryScanExcludesVendorByDefault(): void
    {
        $dir = sys_get_temp_dir() . '/mgscan_' . bin2hex(random_bytes(4));
        mkdir($dir . '/vendor', 0777, true);
        file_put_contents($dir . '/app.php', '<?php mail($_POST["e"], "s", "b");');
        file_put_contents($dir . '/vendor/lib.php', '<?php mail("vendor@example.com", "s", "b");');

        $findings = (new SinkScanner())->scan($dir);
        $files = array_unique(array_map(static fn(Finding $f): string => $f->file, $findings));
        self::assertContains($dir . '/app.php', $files);
        self::assertNotContains($dir . '/vendor/lib.php', $files);

        unlink($dir . '/app.php');
        unlink($dir . '/vendor/lib.php');
        rmdir($dir . '/vendor');
        rmdir($dir);
    }
}
