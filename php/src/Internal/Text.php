<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Internal;

/** @internal */
final class Text
{
    private function __construct()
    {
    }

    /**
     * What a child process or a server said, cut to a length and reduced to
     * printable ASCII, so it can sit in an exception message that reaches a
     * log line whatever bytes the other side wrote.
     */
    public static function printable(string $text, int $max = 200): string
    {
        $text = substr(trim($text), 0, $max);

        return preg_replace('/[^\x20-\x7E]/', '?', $text) ?? '';
    }
}
