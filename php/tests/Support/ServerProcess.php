<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Tests\Support;

/** A running `aprv serve`; {@see stop()} ends it. */
final class ServerProcess
{
    /**
     * @param resource $process
     * @param array<int, resource> $pipes
     */
    public function __construct(
        private $process,
        private array $pipes,
        public readonly string $url,
        private readonly ?string $tokenFile,
    ) {
    }

    public function stop(): void
    {
        proc_terminate($this->process);
        foreach ($this->pipes as $pipe) {
            if (is_resource($pipe)) {
                fclose($pipe);
            }
        }
        proc_close($this->process);
        if ($this->tokenFile !== null) {
            @unlink($this->tokenFile);
        }
    }
}
