<?php

namespace Modules\AI\Contracts;

interface AIProviderInterface
{
    public function generate(string $prompt, ?string $imageUrl = null, array $options = []): string;
    public function getName(): string;
}
