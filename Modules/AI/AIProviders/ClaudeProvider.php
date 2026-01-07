<?php

namespace Modules\AI\AIProviders;

class ClaudeProvider
{
    public function getName(): string
    {
        return 'Claude';
    }

    public function generate(string $prompt,?string $imageUrl = null,  array $options = []): string{

    }
}
