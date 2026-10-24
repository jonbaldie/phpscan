<?php
// Taint classes, sanitizers, propagation and suppression. A trailing expect
// comment lists the rules a line must report; no other line may report any.

// --- sources reach sinks directly
mysqli_query($db, "SELECT * FROM t WHERE a = " . $_GET['a']); // expect: PHP-SQLI
shell_exec('ls ' . $_POST['dir']); // expect: PHP-CMDI
echo `ping {$_GET['host']}`; // expect: PHP-CMDI PHP-XSS
assert($_REQUEST['x']); // expect: PHP-CODEI
print $_COOKIE['c']; // expect: PHP-XSS
readfile($_GET['f']); // expect: PHP-PATH
require $_GET['mod']; // expect: PHP-LFI
file_get_contents($_GET['u']); // expect: PHP-PATH
unserialize($_COOKIE['state']); // expect: PHP-DESER
extract($_POST); // expect: PHP-VAROVR

// --- sanitizers
mysqli_query($db, "SELECT * FROM t WHERE a = " . intval($_GET['a']));
mysqli_query($db, "SELECT * FROM t WHERE a = '" . mysqli_real_escape_string($db, $_GET['a']) . "'");
shell_exec('ls ' . escapeshellarg($_POST['dir']));
echo htmlspecialchars($_GET['q']);
echo (int) $_GET['n'];
readfile(basename($_GET['f']));
echo json_encode($_GET); // expect: PHP-XSS

// --- decoding after a sanitizer restores what it removed (pattern of CVE-2026-115497)
readfile(wp_kses_decode_entities(basename($_GET['f']))); // expect: PHP-PATH
echo html_entity_decode(htmlspecialchars($_GET['q'])); // expect: PHP-XSS
readfile(basename(wp_kses_decode_entities($_GET['f'])));
echo htmlspecialchars_decode(intval($_GET['n']));

// --- propagation through variables, arrays, concatenation, interpolation
$a = $_GET['a'];
$b = "pre-$a-post";
$c = ['k' => $b];
$d = strtoupper(trim($c['k']));
echo $d; // expect: PHP-XSS
$e = $d;
$e = 'constant';
echo $e;

// --- branches join
if ($x) {
    $v = $_GET['v'];
} else {
    $v = 'safe';
}
system($v); // expect: PHP-CMDI

// --- loops
foreach ($_POST['items'] as $item) {
    echo $item; // expect: PHP-XSS
}

// --- user functions: sink inside, report at the call that feeds it
function run_cmd($cmd, int $n) {
    passthru($cmd);
}
run_cmd($_GET['cmd'], 1); // expect: PHP-CMDI
run_cmd('uptime', $_GET['n']);

function clean($s) {
    return htmlspecialchars($s);
}
function pass($s) {
    return $s;
}
echo clean($_GET['s']);
echo pass($_GET['s']); // expect: PHP-XSS

// --- closures and arrow functions
$f = fn($x) => $x . '!';
echo $f($_GET['z']); // expect: PHP-XSS

// --- prepared statements are fine
$st = $pdo->prepare('SELECT * FROM t WHERE a = ?');
$st->execute([$_GET['a']]);
$pdo->query('SELECT * FROM t WHERE a = ' . $_GET['a']); // expect: PHP-SQLI

// --- decoder after a sanitizer inside a called function restores sink taint
function open_decoded_path($path) {
    $path = wp_kses_decode_entities($path);
    fopen($path, 'rb');
}
open_decoded_path(basename($_GET['file'])); // expect: PHP-PATH

function open_path($path) {
    fopen($path, 'rb');
}
open_path(basename($_GET['file']));
open_decoded_path(intval($_GET['file']));

// --- suppression
echo $_GET['trusted']; // phpscan-ignore
// phpscan-ignore
echo $_GET['trusted2'];
