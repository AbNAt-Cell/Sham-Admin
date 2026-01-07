<?php

namespace Modules\AI\PromptTemplates;

use Modules\AI\Contracts\PromptTemplateInterface;

class GenerateTitleFromImageTemplate implements PromptTemplateInterface
{

    public function build(?string $context = null, ?string $langCode = null, ?string $description = null, ?string $category_id = null): string
    {
        $langCode ??= 'en';
        $langCode = strtoupper($langCode);

        return <<<PROMPT
            You are an advanced professional food and product listing analyst with strong skills in image recognition.

            Analyze the uploaded product image provided by the user.
            Your task is to generate a clean, concise, and professional product name suggestion suitable for online menus or food listings.

            CRITICAL INSTRUCTIONS:
            - The output must be 100% in {$langCode} — this is mandatory.
            - Identify the main food item or product shown in the image.
            - Do not include brand names, adjectives, or descriptions like "tasty", "fresh", or "best".
            - Keep it short (35–70 characters), plain, and suitable for listing titles.
            - Return only the translated product title as plain text in {$langCode}.

            IMPORTANT:
            - If the image is not relevant to food or menu products (e.g., clothing, landscapes, documents, or random objects), respond only with the word "INVALID_INPUT".
            - Do not include any explanations, apologies, or extra formatting.

         PROMPT;
    }

    public function getType(): string
    {
       return 'generate_title_from_image';
    }
}
