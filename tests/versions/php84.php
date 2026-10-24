<?php
// PHP 8.4: property hooks, asymmetric visibility, `new` without
// parentheses, #[\Deprecated], array_find().

class Page {
    public private(set) string $title = '';

    public string $slug {
        set(string $value) {
            $this->slug = strtolower($value);
        }
        get => $this->slug;
    }

    public function __construct(string $title) {
        $this->title = $title;
    }

    #[\Deprecated(message: 'use render()')]
    public function show(string $body): void {
        echo $body;
    }

    public function include_theme(string $theme): void {
        include __DIR__ . '/themes/' . $theme . '.php';
    }
}

$len = new Page('home')->title;

$p = new Page('home');
$p->show($_GET['body']); // expect: PHP-XSS
$p->include_theme($_COOKIE['theme']); // expect: PHP-LFI

$hit = array_find([1, 2, 3], fn(int $n) => $n > 1);
$target = $_GET['url'];
$ch = curl_init($target); // expect: PHP-SSRF
