<?php

namespace Modules\AI\PromptTemplates;

use Modules\AI\Contracts\PromptTemplateInterface;
use Modules\AI\Services\ProductResourceService;

class GeneralSetupTemplates implements  PromptTemplateInterface
{
    protected ProductResourceService $productResource;

    public function __construct()
    {
        $this->productResource = new ProductResourceService();
    }

    public function build(?string $context = null, ?string $langCode = null, ?string $description = null): string
    {
        $resource = $this->productResource->productGeneralSetupData();
        $allCategories      = $resource['categories'];
        $allSubCategories   = $resource['sub_categories'];
        $categories = implode("', '", array_keys($allCategories));
        $subCategories = implode("', '", array_keys($allSubCategories));

       return <<<PROMPT

                 You are an intelligent food product classification assistant for a food delivery system.

                 Analyze the following product information carefully:
                 - Name: '{$context}'
                 - Description: '{$description}'

                 Your goal is to identify the most accurate product details and return them strictly as a valid JSON object.

                 === OUTPUT STRUCTURE ===
                    {
                      "category_name": "Category name",        // MUST be one of the main categories
                      "sub_category_name": "Sub-category name", // MUST belong to the selected main category
                      "item_type": "product/set_menu",          // Choose between 'product' or 'set_menu'
                      "product_type": "veg/non_veg"             // Choose between 'veg' or 'non_veg'
                    }

                 === STRICT REQUIREMENTS ===
                    1. ENFORCE correct category hierarchy (main → sub).
                    2. USE ONLY these available options — they are case-sensitive and fixed.
                    3. SELECT the most relevant and specific match based on name and description.
                    4. DETERMINE veg/non_veg logically from ingredients or context.
                    5. ALWAYS include all four fields in the JSON output.

                 === AVAILABLE OPTIONS ===
                 [MAIN CATEGORIES] '{$categories}'
                 [SUB CATEGORIES] '{$subCategories}'

                 === RESPONSE FORMAT RULE  ===
                    - If '{$context}' or '{$description}' are unrelated to food or drinks, invalid, nonsensical, or empty — respond ONLY with: INVALID_INPUT
                    - Output ONLY the JSON object or the single word "INVALID_INPUT"
                    - Do NOT create new categories or options.
                    - Do NOT include comments, explanations, or any text outside the JSON.
                    - Do NOT wrap the JSON in ```json or any other code block.
                    - Do NOT wrap the JSON in backticks or markdown.
                    - Ensure the JSON is perfectly valid for PHP json_decode() parsing.

                 PROMPT;

    }

    public function getType(): string
    {
        return 'general_setup';
    }

}
