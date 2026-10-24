<?php
// PHP 8.3: typed class constants, #[\Override], dynamic class constant
// fetch, readonly anonymous classes, json_validate().

interface Runner {
    const string BIN = '/usr/bin/convert';
    public function run(string $arg): void;
}

class Converter implements Runner {
    const string FLAGS = '-strip';

    #[\Override]
    public function run(string $arg): void {
        system(self::BIN . ' ' . self::FLAGS . ' ' . $arg);
    }

    public function safe(string $arg): void {
        system(self::BIN . ' ' . escapeshellarg($arg));
    }
}

$name = 'FLAGS';
$flags = Converter::{$name};

$c = new Converter();
$c->run($_POST['file']); // expect: PHP-CMDI
$c->safe($_POST['file']);

$cfg = new readonly class('x') {
    public function __construct(public string $v) {}
};

$raw = file_get_contents('php://input');
if (json_validate($raw)) {
    $data = json_decode($raw, true);
    eval($data['code']); // expect: PHP-CODEI
}
