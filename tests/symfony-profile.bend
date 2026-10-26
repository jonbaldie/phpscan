import Base
import ../src/symfony.bend as P
import ../src/advisories.bend as A
import ../src/lex.bend as L

def evidence(e: P.Evidence, expected: U32) -> Bool:
  match e:
    case P.Evidence{sites, inc}:
      Bool.not(inc) && U32.is_eq(U32.from_nat(List.length(&2, P.Site, sites)), expected)

def source(typ: String, setup: String, prefix: String) -> String:
  "<?php namespace App; use Illuminate\\Http\\Request as WebRequest; class Access { function handle(" ++ typ ++ " $request) { " ++ setup ++ " if (str_starts_with($request->getPathInfo(), '" ++ prefix ++ "')) { abort_unless(auth()->check(), 403); } } }"

def matches(version: String, package: String, expected: U32) -> Bool:
  U32.is_eq(U32.from_nat(List.length(&2, A.Finding, A.scan("{\"packages\":[{\"name\":\"" ++ package ++ "\",\"version\":\"" ++ version ++ "\"}]}"))), expected)

def main() -> U32:
  ok = evidence(P.scan("a.php", source("WebRequest", "", "/admin")), 1) &&
    evidence(P.scan("a.php", source("\\Symfony\\Component\\HttpFoundation\\Request", "", "/admin")), 1) &&
    evidence(P.scan("a.php", source("Request", "", "/admin")), 0) &&
    evidence(P.scan("a.php", source("WebRequest", "$request = other();", "/admin")), 0) &&
    evidence(P.scan("a.php", source("WebRequest", "", "admin")), 0) &&
    evidence(P.scan("a.php", source("Other|WebRequest", "", "/admin")), 0) &&
    matches("7.3.6", "symfony/http-foundation", 1) &&
    matches("7.3.7", "symfony/http-foundation", 0) &&
    matches("5.99.0", "symfony/http-foundation", 0) &&
    matches("1.0.0", "symfony/http-foundation", 1) &&
    matches("1.0.0", "symfony/symfony", 0) &&
    matches("dev-main", "symfony/http-foundation", 1) &&
    matches("3.6.3", "livewire/livewire", 1)
  L.sel(U32, ok, u => 0, u => 1)
