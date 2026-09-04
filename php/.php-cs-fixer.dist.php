<?php

declare(strict_types=1);

return (new PhpCsFixer\Config())
    ->setRiskyAllowed(false)
    ->setRules([
        '@PER-CS2.0' => true,
        'declare_strict_types' => true,
        'ordered_imports' => ['sort_algorithm' => 'alpha'],
        'no_unused_imports' => true,
    ])
    ->setFinder(
        PhpCsFixer\Finder::create()
            ->in(__DIR__ . '/src')
            ->in(__DIR__ . '/tests')
    );
