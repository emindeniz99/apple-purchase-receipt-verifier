<?php

declare(strict_types=1);

return (new PhpCsFixer\Config())
    ->setRiskyAllowed(true)
    ->setRules([
        '@PSR12' => true,
        'declare_strict_types' => true,
        'ordered_imports' => ['sort_algorithm' => 'alpha'],
        'no_unused_imports' => true,
    ])
    ->setFinder(
        PhpCsFixer\Finder::create()
            ->in(__DIR__ . '/src')
            ->in(__DIR__ . '/tests')
            // The fuzz targets are format-checked too — the same split the
            // Rust port makes, where `cargo fmt --check` runs in rust/fuzz
            // while clippy does not. `fuzz/tools`, `fuzz/corpus` and
            // `fuzz/crashes` are the fuzzer's own working directories and
            // hold no source.
            ->in(__DIR__ . '/fuzz')
            ->exclude(['tools', 'corpus', 'crashes', 'coverage'])
    );
