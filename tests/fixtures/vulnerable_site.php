<?php
// Fixture for SinkScanner tests — intentionally vulnerable patterns.

// 1. Classic header injection into mail() with fifth-parameter abuse
$to = $_POST['email'];
$subject = "Password reset";
$headers = "From: noreply@example.com\r\n";
$headers .= "Bcc: " . $_POST['bcc'] . "\r\n";
mail($to, $subject, $body, $headers, '-f' . $_GET['sender']);

// 2. wp_mail with raw superglobal
wp_mail($_REQUEST['mail'], 'Hi', $body, ['From: ' . $_POST['from']]);

// 3. PHPMailer usage
$mail = new PHPMailer(true);
$mail->setFrom($_POST['from'], 'Site');
$mail->addAddress($userEmail, $userName);
$mail->addCustomHeader('X-Token', $_POST['token']);
$mail->send();

// 4. Swift Mailer
$message = (new Swift_Message('Subject'))
    ->setFrom(['noreply@example.com' => 'Site'])
    ->setTo([$_POST['email'] => 'User'])
    ->setBody($body);
$transport = new Swift_SendmailTransport('/usr/sbin/sendmail -bs');
$mailer = new Swift_Mailer($transport);
$mailer->send($message);

// 5. Symfony
$email = (new Email())
    ->from('noreply@example.com')
    ->to($request->get('email'))
    ->subject('Reset')
    ->text($body);
$symfonyMailer->send($email);

// 6. mb_send_mail with extra params
mb_send_mail($to, $subj, $body, $hdr, '-r' . $returnPath);

// 7. Safe-ish literal call (should be info/warning at most)
mail('ops@example.com', 'Deploy done', 'all good');
