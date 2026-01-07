<?php

namespace Modules\AI\PromptTemplates;

use Modules\AI\Contracts\PromptTemplateInterface;

class ProductNameTemplate implements  PromptTemplateInterface
{
    public function build(?string $context = null, ?string $langCode = null, ?string $description = null, ?string $category_id = null): string
    {
        $langCode = strtoupper($langCode);

        return <<<PROMPT
          You are an expert copywriter for an online food delivery platform.

          Your task: Rewrite the food item name "{$context}" into a clean, natural, and concise food title suitable for menu listings.

          CRITICAL INSTRUCTION:
          - The output must be 100% in {$langCode} — this is mandatory.
          - If the original name is not in {$langCode}, translate it accurately while keeping the food meaning.
          - Do not mix languages; use only {$langCode} characters and words.
          - Keep it short, between 35–70 characters, natural, and appealing for a food delivery app.
          - Do NOT include brand names, emojis, extra punctuation, or marketing phrases.
          - Return only the final translated title as plain text in {$langCode} — no explanations.

          VALIDATION RULES:
          - Process only food-related names (e.g., burgers, pizza, biryani, noodles, beverages, meal sets, desserts, etc.).
          - If the input is not food-related, return exactly: INVALID_INPUT
          - If the input is meaningless or cannot be converted into a valid food title, return exactly: INVALID_INPUT
          - Do not generate fallback messages, guesses, or partial translations.

      PROMPT;
    }

    public function getType(): string
    {
        return 'product_name';
    }
}
