<?php

namespace Modules\AI\AIProviders;

use Modules\AI\Contracts\AIProviderInterface;
use OpenAI;

class OpenAIProvider implements AIProviderInterface
{
    protected string $apiKey;
    protected ?string $organization;

    public function getName(): string
    {
        return 'OpenAI';
    }

    public function setApiKey($apikey): void
    {
        $this->apiKey = $apikey;
    }

    public function setOrganization($organization): void
    {
        $this->organization = $organization;
    }

    public function generate(string $prompt, ?string $imageUrl = null, array $options = []): string
    {
        $client = OpenAI::client($this->apiKey, $this->organization);
        $content = [['type' => 'text', 'text' => $prompt]];
        if (!empty($imageUrl)) {
            $content[] = [
                'type' => 'image_url',
                'image_url' => ['url' => $imageUrl],
            ];
        }
        $response = $client->chat()->create([
            'model' => 'gpt-4o',
            'messages' => [
                [
                    'role' => 'user',
                    'content' => $content,
                ],
            ],
            'temperature' => 0.3,
        ]);
        return $response->choices[0]->message->content;
    }
}
