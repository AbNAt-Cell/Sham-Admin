<?php

namespace Modules\AI\AIProviders;

use Illuminate\Support\Facades\Cache;
use Modules\AI\app\Exceptions\ValidationException;
use Modules\AI\app\Models\AISetting;
use Modules\AI\Services\AIResponseValidatorService;

class AIProviderManager
{
    protected array $providers;

    public function __construct(array $providers)
    {
        $this->providers = $providers;
    }

    public function getAvailableProviderObject()
    {
        $activeAiProvider = $this->getActiveAIProvider();
        foreach ($this->providers as $provider) {
            if ($activeAiProvider->ai_name == $provider->getName()) {
                $provider->setApiKey($activeAiProvider->api_key);
                $provider->setOrganization($activeAiProvider->organization_id);
                return $provider;
            }
        }

    }
    public function getActiveAIProvider(): AISetting
    {
        $provider = Cache::remember('active_ai_provider', 60, function () {
            return AISetting::where('status', 1)
                ->whereNotNull('api_key')
                ->where('api_key', '!=', '')
                ->first();
        });

        if (!$provider) {
            throw new \RuntimeException('No active AI provider available at this moment.');
        }
        return $provider;
    }

    public function generate(string $prompt, ?string $imageUrl = null, array $options = []): string
    {
        $providerObject = $this->getAvailableProviderObject();
        $activeProvider = $this->getActiveAIProvider();
        $response = $providerObject->generate($prompt, $imageUrl);
        $aiValidator = new AIResponseValidatorService();
        $appMode = env('APP_MODE');
        $section = $options['section'] ?? '';

        if ($appMode === 'demo') {
            $ip = request()->header('x-forwarded-for');
            $cacheKey = 'demo_ip_usage_' . $ip;
            $count = Cache::get($cacheKey, 0);
            if ($count >= 10) {
                throw new ValidationException("Demo limit reached: You can only generate 10 times.");
            }
            Cache::forever($cacheKey, $count + 1);
        }
        $validatorMap = [
            'product_name' => 'validateProductTitle',
            'product_short_description' => 'validateProductShortDescription',
            'general_setup' => 'validateProductGeneralSetup',
            'pricing_and_others' => 'validateProductGeneralSetup',
            'stock_setup' => 'validateStockSetup',
            'addon_setup' => 'validateAddonSetup',
            'search_tag_setup' => 'validateTagSetup',
            'cuisine_setup' => 'validateCuisineSetup',
            'variation_setup' => 'validateProductVariationSetup',
            'generate_product_title_suggestion' => 'validateProductTitleSuggestion',
            'generate_title_from_image' => 'validateImageResponse',
        ];

        if ($section && isset($validatorMap[$section])) {
            $aiValidator->{$validatorMap[$section]}($response, $options['context'] ?? null);
        }

        return $response;
    }

}
