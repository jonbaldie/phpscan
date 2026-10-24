<?php
// PHP 8.2: readonly classes, DNF types, standalone true/false/null types,
// constants in traits, enums (8.1) with methods.

enum Mode: string {
    case Raw = 'raw';
    case Safe = 'safe';

    public function label(): string {
        return ucfirst($this->value);
    }
}

trait HasTable {
    public const TABLE = 'users';
}

readonly class Query {
    use HasTable;

    public function __construct(public string $where) {}

    public function run(\PDO $db): array|false {
        return $db->query('SELECT * FROM ' . self::TABLE . ' WHERE ' . $this->where)->fetchAll();
    }
}

function find((Countable&Traversable)|null $rows, string $name): true {
    $pdo = new PDO('sqlite::memory:');
    $pdo->query("SELECT * FROM users WHERE name = '$name'");
    return true;
}

function nothing(): null {
    return null;
}

find(null, $_GET['name']); // expect: PHP-SQLI

$id = (int) $_GET['id'];
$pdo = new PDO('sqlite::memory:');
$pdo->query("SELECT * FROM users WHERE id = $id");

$mode = Mode::tryFrom($_GET['mode'] ?? 'raw') ?? Mode::Raw;
echo htmlspecialchars($_GET['q'] ?? '', ENT_QUOTES);
echo $_GET['q']; // expect: PHP-XSS
