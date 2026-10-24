<?php
// PHP 8.5: pipe operator, clone with, #[\NoDiscard], (void) cast,
// array_first()/array_last(), closures in constant expressions.

final class Cfg {
    public function __construct(public readonly string $path = '/tmp') {}
}

#[\NoDiscard]
function load(string $path): string {
    return file_get_contents($path);
}

(void) load($_GET['p']); // expect: PHP-PATH

$cfg = clone(new Cfg(), ['path' => '/var']);

$name = $_GET['name'] |> trim(...) |> strtolower(...);
echo $name; // expect: PHP-XSS

$safe = $_GET['name'] |> trim(...) |> htmlspecialchars(...);
echo $safe;

$first = array_first($_POST['ids'] ?? []);
$last = array_last([1, 2, 3]);
unserialize($first); // expect: PHP-DESER

header('Location: ' . $_GET['next']); // expect: PHP-HEADER
