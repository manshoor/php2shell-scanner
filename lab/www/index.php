<?php
// Minimal lab page. Starts a session so a PHPSESSID cookie is sent (lets the
// scanner recognise PHP even when the version header is suppressed), and prints
// the running version for human confirmation. No application logic, no secrets.
session_start();
header('Content-Type: text/plain');
echo "php2shell patch-validation lab\n";
echo "PHP " . PHP_VERSION . "\n";
