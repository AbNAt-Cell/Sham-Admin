<?php

namespace Modules\AI\PromptTemplates;

use Modules\AI\Contracts\PromptTemplateInterface;

class PricingTemplate implements  PromptTemplateInterface
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

              Your task is to determine appropriate pricing, stock, and discount details based on the food type, quality, portion size, and market logic.

              === OUTPUT REQUIREMENTS ===
              Return ONLY a valid JSON object with the following exact fields:

                {
                  "price": 120.00,               // Regular selling price (decimal)
                  "discount_type": "amount",       // Use either "amount" or "percent"
                  "discount": 0.00,              // Discount value (numeric)
                  "tax_type": "percent",         // Use either "amount" or "percent"
                  "tax": 5.00                    // Tax amount or percentage (numeric)
                }

              === CRITICAL INSTRUCTIONS ===

                1. Output MUST be **pure JSON text on a single line** — no markdown, no code blocks, no triple quotes, no indentation, no explanations.
                2. The JSON must be perfectly valid for PHP json_decode().
                3. Round all numeric values to two decimal points.
                4. Use realistic and consistent food delivery pricing logic:
                   - Fast food items (e.g., burgers, drinks): low to mid-range prices.
                   - Full meals or set menus: higher prices.
                5. Always include all 5 required fields.
                6. Use logical discount and tax values (never null or empty).
                7. Use "percent" for tax_type unless the product explicitly has a fixed tax.

                === VALIDATION RULES ===
                - If the given name or description are unrelated to food, drink, or edible products — respond ONLY with: INVALID_INPUT
                - Output either:
                  - A valid JSON object (as shown above), or
                  - The single word: INVALID_INPUT
                - Absolutely no extra symbols, formatting, or explanation outside the JSON.
                At the end, output the JSON in a single line without any quotes, markdown, or formatting characters.


              PROMPT;
    }

    public function getType(): string
    {
        return 'pricing_and_others';
    }
}
