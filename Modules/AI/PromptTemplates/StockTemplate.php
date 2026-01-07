<?php

namespace Modules\AI\PromptTemplates;

use Modules\AI\Contracts\PromptTemplateInterface;

class StockTemplate implements  PromptTemplateInterface
{
    public function build(?string $context = null, ?string $langCode = null, ?string $description = null): string
    {
        $productInfo = $description
            ? "Product name: \"{$context}\". Description: \"" . addslashes($description) . "\"."
            : "Product name: \"{$context}\".";

        return <<<PROMPT
              You are a professional pricing and inventory analyst for a food delivery system.

              Analyze the following product information carefully:
              {$productInfo}

              Your task is to determine appropriate stock setup details based on the type of food, demand frequency, and serving capacity.

              === OUTPUT REQUIREMENTS ===
              Return ONLY a valid JSON object with the following exact fields:

              {
                  "stock_type": "unlimited",   // Choose one: "unlimited", "daily", or "fixed"
                  "product_stock": 10          // Integer (only required if stock_type is "daily" or "fixed")
              }

              === LOGIC GUIDELINES ===

              1. "unlimited" → for items prepared on demand (e.g., burgers, sandwiches, soft drinks, coffee).
              2. "daily" → for dishes prepared in limited batches each day (e.g., biryani, buffet items, chef specials).
              3. "fixed" → for products with pre-packed or restricted stock (e.g., bottled drinks, frozen meals, desserts sold by count).
              4. "product_stock" must:
                    - Be realistic and vary logically (5–30 for daily, 10–200 for fixed).
                    - Be omitted or small (e.g., 0–5) if the product is rarely available.
              5. Never always default to the same values. Analyze the name and description context carefully before deciding.
              6. Always include both fields, even if "product_stock" is small or not relevant.

              === VALIDATION RULES ===

              - If the given name or description are unrelated to food, drink, or edible products — respond ONLY with: INVALID_INPUT
              - Output either:
                  - A valid JSON object (as shown above), or
                  - The single word: INVALID_INPUT
              - Absolutely no extra symbols, formatting, or explanation outside the JSON.
              -At the end, output the JSON in a single line without any quotes, markdown, or formatting characters.

              PROMPT;
    }

    public function getType(): string
    {
        return 'stock_setup';
    }
}
