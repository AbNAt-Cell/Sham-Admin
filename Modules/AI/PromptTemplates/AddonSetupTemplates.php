<?php

namespace Modules\AI\PromptTemplates;

use Modules\AI\Contracts\PromptTemplateInterface;
use Modules\AI\Services\ProductResourceService;

class AddonSetupTemplates implements  PromptTemplateInterface
{
    protected ProductResourceService $productResource;

    public function __construct()
    {
        $this->productResource = new ProductResourceService();
    }

    public function build(?string $context = null, ?string $langCode = null, ?string $description = null): string
    {
        $resource = $this->productResource->productAddonSetupData();
        $allAddons = $resource['addons'];
        $addons = implode("', '", array_keys($allAddons));

       return <<<PROMPT

                 You are a professional food product configuration assistant for a food delivery system.

                 Analyze the following product information carefully:
                 - Name: '{$context}'
                 - Description: '{$description}'

                 Your task is to determine which available addons are logically suitable for this product based on its category, flavor profile, and typical customer pairing behavior.

                 === OUTPUT STRUCTURE ===
                 Return ONLY a valid JSON object with the following exact fields:

                    {
                      "addon_name": ["Cheese", "Extra Sauce"]   // List of addon names chosen from the available options
                    }

                 === SELECTION LOGIC ===
                    1. Choose addons that logically complement the product:
                       - For burgers, sandwiches, or wraps → sauces, cheese, fries, drinks.
                       - For pizzas → extra cheese, toppings, dips, drinks.
                       - For drinks → ice, flavor shots, lemon, sugar syrup.
                       - For desserts → toppings, extra syrup, ice cream scoop.
                       - For combo or meal items → drinks or sides that enhance the experience.
                    2. Select 1–3 addons maximum.
                    3. Use only addon names from the provided list.
                    4. If no relevant addons fit, return an empty array: {"addon_name": []}.

                 === AVAILABLE ADDONS ===
                    ['{$addons}']

                 **Output Format Rule:**
                   Return ONLY the raw JSON object — no code blocks, no markdown, no explanation, no labels, no timestamps, no extra text, no triple backticks (``` or ```json```). The response must start with "{" and end with "}".

                 PROMPT;

    }

    public function getType(): string
    {
        return 'addon_setup';
    }

}
