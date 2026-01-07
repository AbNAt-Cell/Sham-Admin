<?php

namespace Modules\AI\PromptTemplates;

use Modules\AI\Contracts\PromptTemplateInterface;

class GenerateProductTitleSuggestionTemplate implements PromptTemplateInterface
{

    public function build(mixed $context = null, ?string $langCode = null, ?string $description = null, ?string $category_id = null): string
    {
        $langCode = strtoupper($langCode);
        $keywordsText = $context;
        if (is_array($context)) {
            $keywordsText = implode(' ', $context);
        }
        return <<<PROMPT
                You are a professional food and product listing title generator for an online restaurant and delivery platform.

               Using the keywords "{$keywordsText}", generate 4 short, natural, and appealing product title suggestions suitable for online menus or food listings.


               CRITICAL INSTRUCTIONS:
               - The output must be 100% in {$langCode}.
               - Titles must be between 25–70 characters.
               - Titles must be unique, descriptive, and natural (avoid repetition).
               - Use the product name and context naturally (e.g., “Spicy Chicken Biryani Bowl” instead of “Biryani”).
               - Avoid unnecessary words like “Delicious”, “Tasty”, “Amazing”, etc.
               - Titles must use the keywords naturally.
               - Each title should sound ready for direct listing in a restaurant menu or online product page.
               - Return exactly 4 titles in **plain JSON** format as shown below (do not include ```json``` or any extra markdown):

               {
                 "titles": [
                   "Title 1",
                   "Title 2",
                   "Title 3",
                   "Title 4"
                 ]
               }

               Do not include any extra explanation, only return the JSON.

               IMPORTANT:
                - If the keywords are not relevant to booking services or is empty, meaningless, or irrelevant to a food or retail product, respond only with the word "INVALID_INPUT".
                - Do not include any additional text, labels, or formatting besides the JSON object itself.

               **Output Format Rule:**
               -Return ONLY the raw JSON object — no code blocks, no markdown, no explanation, no labels, no timestamps, no extra text, no triple backticks (``` or ```json```). The response must start with "{" and end with "}".

               PROMPT;
    }
    public function getType(): string
    {
        return "generate_product_title_suggestion";
    }

}
