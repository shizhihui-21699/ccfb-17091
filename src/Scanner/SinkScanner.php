<?php

declare(strict_types=1);

namespace MailGuard\Scanner;

/**
 * Static, token-based scanner for email-sending sinks and injection-prone
 * patterns across a PHP codebase.
 *
 * It is deliberately heuristic rather than a full dataflow engine: its job is
 * to enumerate EVERY place that can send mail or build mail headers, then
 * rank them so manual review starts at the dangerous ones. Token parsing
 * means comments and string contents are never mistaken for calls.
 *
 * Detected:
 *  - native mail() incl. the fifth $additional_parameters argument (CWE-88)
 *  - wp_mail(), PHPMailer, Swift Mailer, Symfony Mailer, Pear Mail call sites
 *  - header-building with CRLF literals / %0d%0a (CWE-93/CWE-113)
 *  - superglobals ($_GET/$_POST/$_REQUEST/$_COOKIE) flowing into mail sinks
 *  - sendmail flags (-f -r -X -o…) concatenated into arguments
 */
final class SinkScanner
{
    /** Plain function names that send mail. */
    private const FUNCTION_SINKS = [
        'mail' => true,
        'wp_mail' => true,
        'mb_send_mail' => true,
        'mail_send' => true, // PEAR Mail::send appears as method; this catches wrappers
    ];

    /** Method names that set addresses/headers on mail libraries. */
    private const METHOD_SINKS = [
        // PHPMailer
        'addaddress' => 'PHPMailer::addAddress',
        'addcc' => 'PHPMailer::addCC',
        'addbcc' => 'PHPMailer::addBCC',
        'setfrom' => 'PHPMailer::setFrom',
        'addreplyto' => 'PHPMailer::addReplyTo',
        'addcustomheader' => 'PHPMailer::addCustomHeader',
        // Swift Mailer 5/6
        'setto' => 'Swift_Message::setTo',
        'setcc' => 'Swift_Message::setCc',
        'setbcc' => 'Swift_Message::setBcc',
        'setreplyto' => 'Swift_Message::setReplyTo',
        'setsubject' => 'Swift_Message::setSubject',
        'setbody' => 'Swift_Message::setBody',
        'addpart' => 'Swift_Message::addPart',
        // Symfony Mime
        'to' => 'Symfony Email::to',
        'cc' => 'Symfony Email::cc',
        'bcc' => 'Symfony Email::bcc',
        'from' => 'Symfony Email::from',
        'replyto' => 'Symfony Email::replyTo',
        'subject' => 'Symfony Email::subject',
        'html' => 'Symfony Email::html',
        'text' => 'Symfony Email::text',
        'addtextheader' => 'Symfony Header::addTextHeader',
        'addheader' => 'generic addHeader',
    ];

    /** Method names that trigger actual transmission. */
    private const SEND_METHODS = ['send' => true, 'msgsend' => true];

    /** Class constructions worth noting. */
    private const CONSTRUCT_SINKS = [
        'phpmailer' => 'PHPMailer',
        'swift_message' => 'Swift_Message',
        'swift_smtptransport' => 'Swift_SmtpTransport',
        'swift_sendmailtransport' => 'Swift_SendmailTransport',
        'swift_mailtransport' => 'Swift_MailTransport',
        'email' => 'Symfony/Mime Email',
        'mail' => 'PEAR Mail',
    ];

    private const SUPERGLOBALS = [
        '$_get' => true, '$_post' => true, '$_request' => true,
        '$_cookie' => true, '$_server' => true, '$_http_get_vars' => true,
        '$_http_post_vars' => true,
    ];

    private const SENDMAIL_FLAGS = '/(?:^|[\s"\'])\\-[froOXQ][\s"\']/';

    /** @var list<string> */
    private array $excludedDirs;

    /**
     * @param list<string> $excludedDirs Directory basenames to skip.
     */
    public function __construct(array $excludedDirs = ['vendor', 'node_modules', '.git', 'tests', 'test'])
    {
        $this->excludedDirs = $excludedDirs;
    }

    /**
     * Scan a file or directory; returns every finding, critical first.
     *
     * @return list<Finding>
     */
    public function scan(string $path): array
    {
        $files = is_dir($path) ? $this->collectPhpFiles($path) : [$path];
        $findings = [];
        foreach ($files as $file) {
            $findings = array_merge($findings, $this->scanFile($file));
        }

        return self::sortFindings($findings);
    }

    /**
     * @param list<Finding> $findings
     * @return list<Finding>
     */
    private static function sortFindings(array $findings): array
    {
        $order = [Finding::SEVERITY_CRITICAL => 0, Finding::SEVERITY_WARNING => 1, Finding::SEVERITY_INFO => 2];
        usort(
            $findings,
            static fn(Finding $a, Finding $b): int =>
                ($order[$a->severity] <=> $order[$b->severity])
                ?: [$a->file, $a->line] <=> [$b->file, $b->line],
        );
        return $findings;
    }

    /**
     * @return list<string>
     */
    private function collectPhpFiles(string $dir): array
    {
        $out = [];
        $it = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS),
        );
        foreach ($it as $file) {
            if (!$file->isFile() || strtolower($file->getExtension()) !== 'php') {
                continue;
            }
            foreach (explode(DIRECTORY_SEPARATOR, (string)$file) as $segment) {
                if (in_array($segment, $this->excludedDirs, true)) {
                    continue 2;
                }
            }
            $out[] = (string)$file;
        }
        sort($out);
        return $out;
    }

    /**
     * @return list<Finding>
     */
    public function scanFile(string $file): array
    {
        $source = file_get_contents($file);
        if ($source === false) {
            return [];
        }
        $tokens = @token_get_all($source);
        $this->fileTokens[$file] = $tokens;
        $lines = preg_split('/\r\n|\r|\n/', $source) ?: [];
        $findings = [];
        $count = count($tokens);

        for ($i = 0; $i < $count; $i++) {
            $token = $tokens[$i];
            if (!is_array($token)) {
                continue;
            }

            // Class constructions: new PHPMailer / new Swift_Message ...
            if ($token[0] === T_NEW) {
                $j = $this->nextSignificant($tokens, $i + 1);
                if ($j !== null && is_array($tokens[$j]) && in_array($tokens[$j][0], [T_STRING, T_NAME_QUALIFIED], true)) {
                    $className = strtolower(ltrim($tokens[$j][1], '\\'));
                    $base = str_contains($className, '\\') ? substr(strrchr($className, '\\'), 1) : $className;
                    if (isset(self::CONSTRUCT_SINKS[$base])) {
                        $findings[] = new Finding(
                            $file,
                            $token[2],
                            Finding::SEVERITY_INFO,
                            'construct:' . self::CONSTRUCT_SINKS[$base],
                            'Mailer construction — verify all inputs pass through MailGuard validation',
                            $this->snippet($lines, $token[2]),
                        );
                    }
                }
            }

            if ($token[0] !== T_STRING) {
                continue;
            }

            $paren = $this->nextSignificant($tokens, $i + 1);
            if ($paren === null || $tokens[$paren] !== '(') {
                continue;
            }

            $prev = $this->previousSignificant($tokens, $i - 1);
            // Skip function/method definitions.
            if ($prev !== null && is_array($tokens[$prev]) && $tokens[$prev][0] === T_FUNCTION) {
                continue;
            }

            $name = strtolower($token[1]);
            $isMethod = $prev !== null && is_array($tokens[$prev])
                && in_array($tokens[$prev][0], [T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR, T_DOUBLE_COLON], true);

            $args = $this->extractArguments($tokens, $paren);

            if (!$isMethod && isset(self::FUNCTION_SINKS[$name])) {
                array_push($findings, ...$this->examineFunctionCall($file, $lines, $name, $token[2], $args));
            } elseif ($isMethod) {
                if (isset(self::SEND_METHODS[$name])) {
                    $findings[] = new Finding(
                        $file,
                        $token[2],
                        Finding::SEVERITY_INFO,
                        'method::send',
                        'Mail-sending call — confirm the message object was built from validated inputs',
                        $this->snippet($lines, $token[2]),
                    );
                } elseif (isset(self::METHOD_SINKS[$name])) {
                    array_push(
                        $findings,
                        ...$this->examineSinkMethod($file, $lines, self::METHOD_SINKS[$name], $token[2], $args),
                    );
                }
            }
        }

        // Second pass: header-shaped string building ("From:", "Bcc:" …)
        // which often happens far from the actual mail() call.
        array_push($findings, ...$this->findHeaderStringBuilding($file, $lines, $tokens));

        return self::sortFindings($findings);
    }

    /**
     * @param array<int, mixed> $tokens
     */
    private function nextSignificant(array $tokens, int $from): ?int
    {
        for ($i = $from, $c = count($tokens); $i < $c; $i++) {
            if (is_array($tokens[$i]) && $tokens[$i][0] === T_WHITESPACE) {
                continue;
            }
            return $i;
        }
        return null;
    }

    /**
     * @param array<int, mixed> $tokens
     */
    private function previousSignificant(array $tokens, int $from): ?int
    {
        for ($i = $from; $i >= 0; $i--) {
            if (is_array($tokens[$i]) && $tokens[$i][0] === T_WHITESPACE) {
                continue;
            }
            return $i;
        }
        return null;
    }

    /**
     * Given the index of an opening parenthesis, return each top-level
     * argument as a list of token indexes.
     *
     * @param array<int, mixed> $tokens
     * @return list<list<int>>
     */
    private function extractArguments(array $tokens, int $openParen): array
    {
        $args = [];
        $current = [];
        $depth = 0;
        for ($i = $openParen, $c = count($tokens); $i < $c; $i++) {
            $t = $tokens[$i];
            if ($t === '(') {
                $depth++;
                if ($depth === 1) {
                    continue;
                }
            } elseif ($t === ')') {
                $depth--;
                if ($depth === 0) {
                    if ($current !== []) {
                        $args[] = $current;
                    }
                    return $args;
                }
            } elseif ($t === ',' && $depth === 1) {
                $args[] = $current;
                $current = [];
                continue;
            }
            if ($depth >= 1) {
                $current[] = $i;
            }
        }
        return $args; // unbalanced source — return what we have
    }

    /**
     * @param array<int, mixed> $tokens
     * @param list<int>        $arg
     * @return array{text:string, line:int, hasSuperglobal:bool, hasCrlf:bool, hasSendmailFlag:bool, hasVariable:bool}
     */
    private function analyseArgument(array $tokens, array $arg): array
    {
        $text = '';
        $line = 0;
        $hasSuperglobal = false;
        $hasCrlf = false;
        $hasSendmailFlag = false;
        $hasVariable = false;

        foreach ($arg as $idx) {
            $t = $tokens[$idx];
            if (is_array($t)) {
                if ($line === 0) {
                    $line = $t[2];
                }
                $text .= $t[1];
                if ($t[0] === T_VARIABLE && isset(self::SUPERGLOBALS[strtolower($t[1])])) {
                    $hasSuperglobal = true;
                }                if ($t[0] === T_VARIABLE) {
                    $hasVariable = true;
                }
                if (in_array($t[0], [T_CONSTANT_ENCAPSED_STRING, T_ENCAPSED_AND_WHITESPACE], true)) {
                    if (preg_match('/\\\\r|\\\\n|%0d|%0a/i', $t[1])) {
                        $hasCrlf = true;
                    }
                }
                if (preg_match(self::SENDMAIL_FLAGS, $t[1] . ' ')) {
                    $hasSendmailFlag = true;
                }
            } else {
                $text .= $t;
                if (preg_match(self::SENDMAIL_FLAGS, $t . ' ')) {
                    $hasSendmailFlag = true;
                }
            }
        }

        return compact('text', 'line', 'hasSuperglobal', 'hasCrlf', 'hasSendmailFlag', 'hasVariable');
    }

    /**
     * @param array<int, mixed>  $tokens
     * @param list<list<int>>    $args
     * @return list<Finding>
     */
    private function examineFunctionCall(string $file, array $lines, string $name, int $line, array $args): array
    {
        $out = [];
        $analysed = array_map(fn(array $a): array => $this->analyseArgument($this->currentTokens($file), $a), $args);

        // mail($to,$subject,$message,$headers,$additional_parameters)
        if ($name === 'mail' || $name === 'mb_send_mail') {
            if (count($args) >= 5) {
                $fifth = $analysed[4];
                $out[] = new Finding(
                    $file,
                    $fifth['line'] ?: $line,
                    Finding::SEVERITY_CRITICAL,
                    'mail():additional_parameters',
                    'Fifth argument ($additional_parameters) reaches the sendmail command line — '
                    . 'remove it entirely, or replace with NativeMailer using a fixed validated -f sender',
                    $this->snippet($lines, $fifth['line'] ?: $line),
                );
            }
            foreach ($analysed as $n => $a) {
                if ($a['hasSendmailFlag']) {
                    $out[] = new Finding(
                        $file,
                        $a['line'] ?: $line,
                        Finding::SEVERITY_CRITICAL,
                        'mail():sendmail-flag',
                        "Argument #{$n} contains a sendmail flag (-f/-r/-X/-o) — argument-injection risk",
                        $this->snippet($lines, $a['line'] ?: $line),
                    );
                }
            }
        }

        foreach ($analysed as $n => $a) {
            if ($a['hasSuperglobal']) {
                $out[] = new Finding(
                    $file,
                    $a['line'] ?: $line,
                    Finding::SEVERITY_CRITICAL,
                    "{$name}():superglobal",
                    "Argument #{$n} of {$name}() reads a request superglobal directly — validate through EmailAddress first",
                    $this->snippet($lines, $a['line'] ?: $line),
                );
            }
            if ($a['hasCrlf']) {
                $out[] = new Finding(
                    $file,
                    $a['line'] ?: $line,
                    Finding::SEVERITY_WARNING,
                    "{$name}():crlf-literal",
                    "Argument #{$n} contains \\r\\n / %0d%0a literals — possible header-injection vector",
                    $this->snippet($lines, $a['line'] ?: $line),
                );
            }
        }

        if ($out === []) {
            $out[] = new Finding(
                $file,
                $line,
                Finding::SEVERITY_WARNING,
                "{$name}()",
                "Call to {$name}() — confirm every argument is a MailGuard-validated value",
                $this->snippet($lines, $line),
            );
        }

        return $out;
    }

    /**
     * @param array<int, mixed>  $tokens
     * @param list<list<int>>    $args
     * @return list<Finding>
     */
    private function examineSinkMethod(string $file, array $lines, string $sink, int $line, array $args): array
    {
        $out = [];
        foreach ($args as $n => $arg) {
            $a = $this->analyseArgument($this->currentTokens($file), $arg);
            if ($a['hasSuperglobal']) {
                $out[] = new Finding(
                    $file,
                    $a['line'] ?: $line,
                    Finding::SEVERITY_CRITICAL,
                    $sink,
                    "Argument #{$n} of {$sink} reads a request superglobal directly",
                    $this->snippet($lines, $a['line'] ?: $line),
                );
            } elseif ($a['hasCrlf']) {
                $out[] = new Finding(
                    $file,
                    $a['line'] ?: $line,
                    Finding::SEVERITY_WARNING,
                    $sink,
                    "Argument #{$n} of {$sink} contains CRLF/encoded-newline literals",
                    $this->snippet($lines, $a['line'] ?: $line),
                );
            } elseif ($a['hasVariable']) {
                $out[] = new Finding(
                    $file,
                    $a['line'] ?: $line,
                    Finding::SEVERITY_WARNING,
                    $sink,
                    "Argument #{$n} of {$sink} is a variable — trace it to a validated EmailAddress/HeaderSet",
                    $this->snippet($lines, $a['line'] ?: $line),
                );
            }
        }

        if ($out === []) {
            $out[] = new Finding(
                $file,
                $line,
                Finding::SEVERITY_INFO,
                $sink,
                "Mail-library call {$sink} with literal arguments",
                $this->snippet($lines, $line),
            );
        }
        return $out;
    }

    /**
     * Find strings that build RFC header lines ("From:", "Bcc:" …), especially
     * interpolated ones — the classic pre-mail() injection pattern.
     *
     * @param array<int, mixed> $tokens
     * @return list<Finding>
     */
    private function findHeaderStringBuilding(string $file, array $lines, array $tokens): array
    {
        $out = [];
        $headerNames = '/^(?:\s)*(?:From|To|Cc|Bcc|Reply-To|Sender|Subject|Content-Type|MIME-Version)\s*:/i';
        $count = count($tokens);
        for ($i = 0; $i < $count; $i++) {
            $t = $tokens[$i];
            if (!is_array($t)) {
                continue;
            }
            $isStringish = in_array($t[0], [T_CONSTANT_ENCAPSED_STRING, T_ENCAPSED_AND_WHITESPACE], true);
            if (!$isStringish) {
                continue;
            }
            $raw = $t[1];
            $stripped = trim($raw, '"\'');
            if (!preg_match($headerNames, $stripped)) {
                continue;
            }

            $interpolated = false;
            if ($t[0] === T_ENCAPSED_AND_WHITESPACE) {
                $interpolated = true;
            } elseif ($t[0] === T_CONSTANT_ENCAPSED_STRING && str_starts_with($raw, '"') && preg_match('/\{\$|\$[a-zA-Z_]/', $raw)) {
                $interpolated = true;
            }

            // An explicit \r or \n inside a header-shaped string is the
            // signature of hand-built header blocks — always warn even when
            // the literal itself is static, since adjacent concatenations are
            // the classic injection sink.
            $containsCrlf = (bool)preg_match('/\\\\[rn]|%0[da]/i', $raw);

            $out[] = new Finding(
                $file,
                $t[2],
                ($interpolated || $containsCrlf) ? Finding::SEVERITY_WARNING : Finding::SEVERITY_INFO,
                'header-string',
                $containsCrlf
                    ? 'Header string contains explicit CR/LF — rewrite via HeaderSet/MimeHeader which rejects control chars'
                    : ($interpolated
                        ? 'Header line built with variable interpolation — route through HeaderSet/MimeHeader'
                        : 'Header line literal — ensure it is never concatenated with raw user input'),
                $this->snippet($lines, $t[2]),
            );
        }
        return $out;
    }

    /**
     * @param list<string> $lines
     */
    private function snippet(array $lines, int $line): string
    {
        $text = $lines[$line - 1] ?? '';
        $text = trim(preg_replace('/\s+/', ' ', $text) ?? '');
        return strlen($text) > 160 ? substr($text, 0, 157) . '...' : $text;
    }

    /**
     * Tokens are stored per scanFile; argument analysis needs them. To keep
     * the helper signatures simple we resolve them through a per-file map.
     *
     * @return array<int, mixed>
     */
    private function currentTokens(string $file): array
    {
        return $this->fileTokens[$file] ?? [];
    }

    /** @var array<string, array<int, mixed>> */
    private array $fileTokens = [];
}
