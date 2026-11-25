<?php

declare(strict_types=1);

namespace MailGuard;

/**
 * A fully-validated outbound message. Construct through the fluent builder;
 * every address and header is checked on the way in, so a Message instance
 * in hand means every field is already safe to render.
 */
final class Message
{
    /** @var list<EmailAddress> */
    private array $to = [];
    /** @var list<EmailAddress> */
    private array $cc = [];
    /** @var list<EmailAddress> */
    private array $bcc = [];
    private ?EmailAddress $from = null;
    private ?EmailAddress $sender = null;
    private ?EmailAddress $replyTo = null;
    private string $subject = '';
    private string $textBody = '';
    private string $htmlBody = '';
    private HeaderSet $customHeaders;

    public function __construct()
    {
        $this->customHeaders = new HeaderSet();
    }

    public static function create(): self
    {
        return new self();
    }

    public function to(EmailAddress ...$recipients): self
    {
        foreach ($recipients as $r) {
            $this->to[] = $r;
        }
        return $this;
    }

    public function cc(EmailAddress ...$recipients): self
    {
        foreach ($recipients as $r) {
            $this->cc[] = $r;
        }
        return $this;
    }

    public function bcc(EmailAddress ...$recipients): self
    {
        foreach ($recipients as $r) {
            $this->bcc[] = $r;
        }
        return $this;
    }

    public function from(EmailAddress $from): self
    {
        $this->from = $from;
        return $this;
    }

    public function sender(EmailAddress $sender): self
    {
        $this->sender = $sender;
        return $this;
    }

    public function replyTo(EmailAddress $replyTo): self
    {
        $this->replyTo = $replyTo;
        return $this;
    }

    public function subject(string $subject): self
    {
        // Store the raw (control-checked) value; encoding happens at render.
        MimeHeader::validateUnstructuredValue($subject, 'subject');
        $this->subject = $subject;
        return $this;
    }

    public function text(string $body): self
    {
        $this->textBody = $body;
        return $this;
    }

    public function html(string $body): self
    {
        $this->htmlBody = $body;
        return $this;
    }

    public function addHeader(string $name, string $value): self
    {
        $this->customHeaders->add($name, $value);
        return $this;
    }

    /** @return list<EmailAddress> */
    public function getTo(): array
    {
        return $this->to;
    }

    /** @return list<EmailAddress> */
    public function getCc(): array
    {
        return $this->cc;
    }

    /** @return list<EmailAddress> */
    public function getBcc(): array
    {
        return $this->bcc;
    }

    public function getFrom(): ?EmailAddress
    {
        return $this->from;
    }

    public function getSender(): ?EmailAddress
    {
        return $this->sender;
    }

    public function getReplyTo(): ?EmailAddress
    {
        return $this->replyTo;
    }

    public function getSubject(): string
    {
        return $this->subject;
    }

    public function getTextBody(): string
    {
        return $this->textBody;
    }

    public function getHtmlBody(): string
    {
        return $this->htmlBody;
    }

    public function getCustomHeaders(): HeaderSet
    {
        return $this->customHeaders;
    }

    /**
     * Final structural check before handing the message to a transport.
     *
     * @throws MailerException
     */
    public function assertSendable(): void
    {
        if ($this->to === [] && $this->cc === [] && $this->bcc === []) {
            throw new MailerException('Message has no recipients');
        }
        if ($this->from === null) {
            throw new MailerException('Message has no From address');
        }
        if ($this->subject === '') {
            throw new MailerException('Message has no subject');
        }
        if ($this->textBody === '' && $this->htmlBody === '') {
            throw new MailerException('Message has no body');
        }
    }
}
