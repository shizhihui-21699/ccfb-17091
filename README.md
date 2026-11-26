# MailGuard — 邮件头注入 / 发信参数注入防护库

针对本次安全事件（找回密码/通知邮件功能存在 **CWE-93 CRLF 邮件头注入** 与
**CWE-88 sendmail 附加参数注入**，后者被利用把日志写入 Web 目录形成可执行脚本）
的统一整改方案。

## 威胁模型与防护点

| 攻击手法 | 入口 | MailGuard 的拦截点 |
|---|---|---|
| 邮箱字段塞 `\r\nBcc: …` 注入收件人/正文 | `mail($to)`、`addAddress($_POST['email'])` | `EmailAddress` 入口拒绝一切 ASCII 控制字符（含 CR/LF/NUL），随后按 RFC 5321/5322 严格解析 |
| 显示名/主题/自定义头注入 | 头字段拼接 | `DisplayName`、`MimeHeader`、`HeaderSet` 全部拒绝控制字符；非 ASCII 走 RFC 2047 编码，折行只由库内部产生 |
| `mail()` 第五参数注入 `-X web目录/shell.php` | `$additional_parameters` | `NativeMailer` 不接受任何用户输入；唯一允许的附加参数是应用配置的固定 `-f` 信封发件人，且二次正则断言 |
| `-f`/`-r` 拼接用户输入 | 发件人字段 | 信封发件人是独立的固定配置 `EmailAddress`，与请求数据物理隔离 |
| 国际化邮箱被误杀 | 含中文/日文/Emoji 域名或 Unicode 本地部分 | 域名经 ext-intl UTS#46 IDNA 转 A-label（`xn--`）；Unicode 本地部分按 SMTPUTF8 能力显式开关 |

## 目录结构

```
src/
  EmailAddress.php         用户邮箱入口（支持 "Name <a@b>" 与逗号列表）
  EmailValidator.php       RFC 5321/5322 严格解析 + IDNA 归一化
  DisplayName.php          显示名校验与 RFC 2047 编码
  MimeHeader.php           安全头值编码（无原始 CR/LF）
  HeaderSet.php            自定义头集合（保留头禁止覆盖）
  Message.php              全量校验后的消息值对象
  MimeBody.php             MIME 组装（QP/base64，正文不可能越界成头）
  NativeMailer.php         原生 mail() 加固封装（第五参数锁死）
  PhpMailerMailer.php      PHPMailer 适配器
  SymfonyMailerMailer.php  Symfony Mailer 适配器（Envelope 钉死）
  SwiftMailerMailer.php   遗留 Swift Mailer 5/6 适配器（无硬依赖）
  WordPressMailer.php      wp_mail() 适配器（phpmailer_init 钉死 Sender）
  MailGuard.php            业务层门面
  Scanner/                 全站发信点静态排查工具
bin/scan                   扫描 CLI（CI 友好，发现 critical 退出码 1）
bin/attack_poc             攻击链端到端复现与拦截验证
tests/                     116 个测试，314 条断言（含 IncidentChainTest 事件链 CI 回归）
```

## 快速接入

### 1. 一次性配置（引导文件里）

```php
use MailGuard\MailGuard;
use MailGuard\EmailAddress;
use MailGuard\NativeMailer;

// 固定信封发件人来自应用配置，永远不碰请求数据
$envelope = EmailAddress::fromUserInput($config['mail']['bounce_address']);
MailGuard::setDefaultMailer(new NativeMailer($envelope));
MailGuard::setDefaultFrom(EmailAddress::fromUserInput(
    $config['mail']['from_address'],
    $config['mail']['from_name'],
));
```

### 2. 密码找回（改造前 → 改造后）

改造前（漏洞代码）：

```php
$to   = $_POST['email'];
$hdr  = "From: noreply@example.com\r\n";
mail($to, 'Reset', $body, $hdr, '-f' . $_GET['sender']);   // 双重注入
```

改造后：

```php
use MailGuard\MailGuard;
use MailGuard\ValidationException;

try {
    $recipient = MailGuard::address($_POST['email']);       // 控制字符在此被拒
} catch (ValidationException $e) {
    // 记录安全日志，按"邮箱格式错误"返回，不泄露内部细节
    return $this->renderValidationError();
}

MailGuard::mailer()->send(
    MailGuard::newMessage('Reset your password')
        ->to($recipient)
        ->text($resetBody),
);
```

### 3. 多库并存时按传输实现选适配器

```php
// PHPMailer
new \MailGuard\PhpMailerMailer($envelope, fn($phpmailer) => $phpmailer->isSMTP() /* 仅配传输 */);

// Symfony Mailer
new \MailGuard\SymfonyMailerMailer($symfonyTransport, $envelope);

// 老 Swift Mailer
new \MailGuard\SwiftMailerMailer($swiftMailer, $envelope);

// WordPress
new \MailGuard\WordPressMailer($envelope);
```

所有适配器构造函数里与地址/头有关的参数都只接受 `EmailAddress` / `Message` /
`HeaderSet`，原始字符串在类型层面就无法传入。

## 排查全部发信点

```bash
php bin/scan --format=text /path/to/site
php bin/scan --format=json --exclude=vendor,cache /path/to/site > audit.json
```

扫描器基于 PHP token 流（不会被注释/字符串误导），覆盖：

- `mail()` / `mb_send_mail()`，**特别是第五个附加参数**（直接判 critical）
- `wp_mail()`、PHPMailer、Swift、Symfony 的全部地址/头发信方法
- 超全局变量（`$_GET/$_POST/$_REQUEST/$_COOKIE`）直接流入发信 sink
- 头形状字符串（`From:`/`Bcc:` …）中的 `\r\n`、`%0d%0a` 字面量
- sendmail 开关（`-f -r -X -o`）拼接
- `new PHPMailer` / `new Swift_Message` 等构造点（info 级，供人工核对）

**关于 warning 与 CI 门禁。** 扫描器只对"确认危险"的模式（超全局直连、
附加参数、sendmail 开关、CRLF 字面量）判 critical 并令进程退出码为 1。
对"变量入参"这类需要人工追溯数据流的情况判 warning —— 因此用本库加固后的
代码自扫描结果是 `0 critical`、退出码 0，但仍会列出适配器内部把**已校验值对象**
传给底层库的 warning。CI 应只对 critical 设门禁；warning 进人工审计清单。
本仓库自身即满足该基线：`php bin/scan src` 退出码为 0。

## 运行验证

```bash
composer test          # 116 tests, 314 assertions
php bin/attack_poc     # 攻击链复现：全部 BLOCKED，正常邮件正常送达
php bin/scan tests/fixtures/vulnerable_site.php   # 退出码 1，可挂 CI
```

`tests/IncidentChainTest.php` 把本次事件的完整攻击链固化为 CI 门禁测试（不依赖手动跑
脚本）：CRLF/编码换行/NUL 注入在地址入口被拒、`-X`/`-oQ` 等 sendmail 负载不是合法地址、
第五参数只会出现固定配置的 `-f`、正常国际化邮件（IDN 域名 punycode、Unicode 主题
RFC 2047、SMTPUTF8 本地部分显式开关）照常送达。

一个关键边界认知：`-rattacker@example.com` 这类字符串其实是**合法的 RFC 5322 地址**
（本地部分允许以连字符开头）。因此 sendmail 开关注入**不能**靠"地址校验拒绝连字符"来防，
那样会误杀真实用户；真正的防线是 `NativeMailer` 的第五参数在类型与构造层面就不接受任何
请求数据，收件人再像开关也只能进入 `$to`，永远到不了命令行。

## 设计取舍（为什么正常用户不会被挡住）

1. **控制字符零容忍，但合法字符全放行。** RFC 5322 的 atext、点原子、引号本地部分
   （策略开关）都支持；拒绝的只有 CR/LF/NUL 这些在正常邮箱里不可能出现的字符。
2. **IDN 在域名层处理，不要求用户输入 punycode。** `user@例え.jp` 自动转
   `user@xn--r8jz45g.jp`，转换结果再做 LDH 标签校验和 IDNA error flag 检查。
3. **Unicode 本地部分默认关、显式开。** 它需要端到端 SMTPUTF8，传统 sendmail 链路
   不支持；开启后仍受 64 字节、点原子规则约束。普通站点只遇到 IDN 域名，默认配置即可。
4. **显示名/主题用 RFC 2047 编码而不是拒绝非 ASCII。** 中文名、日文名、Emoji 都能
   正常发出，且编码过程不可能产生裸 CR/LF。
5. **单标签域名、IP 字面量默认拒绝**（公开网站邮件场景），但保留策略开关供内网用。

## 服务器侧纵深防御（配置层，代码之外也要做）

- `php.ini`：`mail.add_x_header=0`（减少信息泄露）；确认使用现代 PHP（内置
  `mail()` 参数过滤 + escapeshellarg）。
- sendmail/Postfix：以低权限用户运行 MTA；Web 根目录禁止执行 MTA 写入的文件
  （`/var/www` 与邮件队列/日志目录分离）。
- 移除 Web 服务器对 `mail.log`、队列目录的写权限；监控 sendmail 命令行中的 `-X`。
- 给发信功能加频率限制与审计日志（`MailLogger` 已预留接口）。
