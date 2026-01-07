<?php

namespace Modules\AI\PromptTemplates;

use Modules\AI\Contracts\PromptTemplateInterface;
use Modules\AI\Services\ProductResourceService;

class CuisineSetupTemplates implements  PromptTemplateInterface
{
    protected ProductResourceService $productResource;

    public function __construct()
    {
        $this->productResource = new ProductResourceService();
    }

    public function build(?string $context = null, ?string $langCode = null, ?string $description = null): string
    {
        $resource = $this->productResource->productCuisineSetupData();
        $allCuisines = $resource['cuisines'];
        $cuisines = implode("', '", array_keys($allCuisines));

       return <<<PROMPT

                 You are a professional food product configuration assistant for a food delivery system.

                 Analyze the following product information carefully:
                 - Name: '{$context}'
                 - Description: '{$description}'

                 Your task is to determine which available cuisine(s) are logically suitable for this product based on for this food item from the available list..

                 === OUTPUT STRUCTURE ===
                 Return ONLY a valid JSON object with the following exact fields:

                    {
                      "cuisine_name": ["Indian", "Chinese", "Japanese", "Italian"]   // List of cuisines names chosen from the available options
                    }

                 === SELECTION LOGIC ===
                    1. Select cuisines that best match the food’s origin, ingredients, or style:
                       - Burgers, fries, hotdogs → "American"
                       - Pizza, pasta → "Italian"
                       - Sushi, ramen → "Japanese"
                       - Chow mein, fried rice → "Chinese"
                       - Biryani, curry → "Indian"
                       - Falafel, shawarma → "Middle Eastern"
                       - Tacos, burritos → "Mexican"
                       - Croissant, baguette → "French"
                    2. Select 1–3 cuisine maximum.
                    3. Use only cuisine names from the provided list.
                    4. If no relevant cuisine fit, return an empty array: {"cuisine_name": []}.

                 === AVAILABLE CUISINES ===
                    ['{$cuisines}']

                 **Output Format Rule:**
                   Return ONLY the raw JSON object — no code blocks, no markdown, no explanation, no labels, no timestamps, no extra text, no triple backticks (``` or ```json```). The response must start with "{" and end with "}".

                 PROMPT;

    }

    public function getType(): string
    {
        return 'cuisine_setup';
    }

}
