<?php

namespace Modules\AI\Services;

use App\CentralLogics\Helpers;
use Modules\AI\AIProviders\AIProviderManager;
use Modules\AI\AIProviders\ClaudeProvider;
use Modules\AI\AIProviders\OpenAIProvider;
use Modules\AI\app\Models\AISetting;

class AIContentGeneratorService
{
    protected array $templates = [];
    protected array $providers;

    public function __construct()
    {
        $this->loadTemplates();
        $this->providers = [new OpenAIProvider(), new ClaudeProvider()];
    }
    protected function loadTemplates(): void
    {
        $templateClasses = [
            'product_name' =>  \Modules\AI\PromptTemplates\ProductNameTemplate::class,
            'product_short_description' =>  \Modules\AI\PromptTemplates\ProductShortDescriptionTemplate::class,
            'general_setup' =>  \Modules\AI\PromptTemplates\GeneralSetupTemplates::class,
            'pricing_and_others' =>  \Modules\AI\PromptTemplates\PricingTemplate::class,
            'stock_setup' =>  \Modules\AI\PromptTemplates\StockTemplate::class,
            'addon_setup' =>  \Modules\AI\PromptTemplates\AddonSetupTemplates::class,
            'cuisine_setup' =>  \Modules\AI\PromptTemplates\CuisineSetupTemplates::class,
            'search_tag_setup' =>  \Modules\AI\PromptTemplates\SearchTagSetupTemplates::class,
            'variation_setup' =>  \Modules\AI\PromptTemplates\ProductVariationSetup::class,
            'generate_product_title_suggestion' =>  \Modules\AI\PromptTemplates\GenerateProductTitleSuggestionTemplate::class,
            'generate_title_from_image' =>  \Modules\AI\PromptTemplates\GenerateTitleFromImageTemplate::class,
        ];
        foreach ($templateClasses as $type => $class) {
            if (class_exists($class)) {
                $this->templates[$type] = new $class();
            }
        }
    }
    public function generateContent(string $contentType, mixed $context = null, string $langCode = 'en', ?string $description = null, ?string $imageUrl = null ): string
    {
        $template = $this->templates[$contentType];
        $prompt = $template->build(context: $context, langCode: $langCode, description: $description);
        $providerManager = new AIProviderManager($this->providers);
        return $providerManager->generate(prompt: $prompt, imageUrl: $imageUrl, options: ['section' => $contentType, 'context' => $context]);
    }
    public function getAnalyizeImagePath($image): array
    {
        $imageName = Helpers::upload('product/ai_product_image/', 'png', $image);
        return $this->ai_product_image_full_path($imageName);
    }
    public function ai_product_image_full_path($image_name): array
    {
        //local
        if (in_array(request()->ip(), ['127.0.0.1', '::1'])) {
            return [
                'imageName' =>$image_name,
                'imageFullPath' =>"https://www.realsimple.com/thmb/SU9YyxI_5dFIurutkkGUe0iieLI=/750x0/filters:no_upscale():max_bytes(150000):strip_icc():format(webp)/real-simple-mushroom-black-bean-burgers-recipe-0c365277d4294e6db2daa3353d6ff605.jpg",
            ];
        }
        // live
        return [
            'imageName' =>$image_name,
            'imageFullPath' => asset(path: 'storage/app/public/product/ai_product_image/'.$image_name)
        ];
    }

    public function deleteAiImage($imageName): void
    {
        Helpers::delete('product/ai_product_image/', $imageName);
    }
    public function getAvailableContentTypes(): array
    {
        return array_keys($this->templates);
    }
}
