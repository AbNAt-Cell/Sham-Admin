<?php

namespace Modules\AI\Response;

use http\Exception\RuntimeException;
use Modules\AI\Services\ProductResourceService;

class ProductResponse
{
    protected ProductResourceService $productResource;
    public function __construct()
    {
        $this->productResource = new ProductResourceService();
    }

    public function productGeneralSetupAutoFillFormat(string $result): array
    {
        $resource = $this->productResource->productGeneralSetupData();

        $data = json_decode($result, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new \InvalidArgumentException('Invalid JSON: ' . json_last_error_msg());
        }

        if (empty($data['category_name']) || !is_string($data['category_name'])) {
            throw new \InvalidArgumentException('The "category_name" field is required and must be a non-empty string.');
        }

        $processedData = $this->productGeneralSetConvertNamesToIds($data, $resource);
        if (!$processedData['success']) {
            return $processedData;
        }
        $data = $processedData['data'];

        $fields = [
            'category_name',
            'sub_category_name',
            'item_type',
            'product_type',
        ];

        foreach ($fields as $field) {
            if (!array_key_exists($field, $data)) {
                $data[$field] = null;
            }
        }

       return $data;

    }

    public function productPriceAndOthersAutoFill($result) : array|\Illuminate\Http\JsonResponse
    {
        $data = json_decode($result, true);

        $fields = [
            'price',
            'discount_type',
            'discount',
            'tax_type',
            'tax',
        ];

        $errors = [];

        foreach ($fields as $field) {
            if (!array_key_exists($field, $data) || $data[$field] === null || $data[$field] === '') {
                $errors[$field] = "$field is required.";
            }
        }

        if (!empty($errors)) {
            return response()->json(
                $this->formatAIGenerationValidationErrors($errors),
                422
            );
        }
        return $data;
    }

    public function productStockSetupAutoFill($result) : array|\Illuminate\Http\JsonResponse
    {
        $data = json_decode($result, true);

        $fields = [
            'stock_type',
            'product_stock',
        ];

        $errors = [];

        foreach ($fields as $field) {
            if (!array_key_exists($field, $data) || $data[$field] === null || $data[$field] === '') {
                $errors[$field] = "$field is required.";
            }
        }

        if (!empty($errors)) {
            return response()->json(
                $this->formatAIGenerationValidationErrors($errors),
                422
            );
        }
        return $data;
    }

    public function productAddonSetupAutoFillFormat(string $result): array
    {
        $resource = $this->productResource->productAddonSetupData();

        $data = json_decode($result, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new \InvalidArgumentException('Invalid JSON: ' . json_last_error_msg());
        }

        if (!is_array($data['addon_name'])) {
            throw new \InvalidArgumentException('The "addon_name" field is required and must be an array.');
        }

        return $data;

    }

    public function productCuisineSetupAutoFillFormat(string $result): array
    {
        $resource = $this->productResource->productCuisineSetupData();

        $data = json_decode($result, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new \InvalidArgumentException('Invalid JSON: ' . json_last_error_msg());
        }

        if (!is_array($data['cuisine_name'])) {
            throw new \InvalidArgumentException('The "cuisine_name" field is required and must be an array.');
        }

        return $data;

    }

    public function productSearchTagSetupAutoFillFormat(string $result): array
    {
        $result = trim($result);
        $result = preg_replace('/^["`\s]+|["`\s]+$/', '', $result);
        $result = preg_replace('/^```(json)?|```$/m', '', $result);
        $data = json_decode($result, true);

        return $data;
    }

    public function variationSetupAutoFill(string $result): array
    {
        // Clean the AI output
        $result = trim($result);
        $result = preg_replace('/^["`\s]+|["`\s]+$/', '', $result);
        $result = preg_replace('/^```(json)?|```$/m', '', $result);

        // Decode JSON
        $data = json_decode($result, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new \InvalidArgumentException('Invalid JSON: ' . json_last_error_msg());
        }

        // Validate the variations structure
        if (!isset($data['variations']) || !is_array($data['variations'])) {
            return ['variations' => []];
        }

        foreach ($data['variations'] as &$variation) {
            // Validate required keys
            $requiredKeys = ['name', 'type', 'required', 'min', 'max', 'values'];
            foreach ($requiredKeys as $key) {
                if (!array_key_exists($key, $variation)) {
                    // Fill default values if missing
                    switch ($key) {
                        case 'name':
                            $variation['name'] = 'New Option';
                            break;
                        case 'type':
                            $variation['type'] = 'multi';
                            break;
                        case 'required':
                            $variation['required'] = false;
                            break;
                        case 'min':
                            $variation['min'] = 1;
                            break;
                        case 'max':
                            $variation['max'] = 1;
                            break;
                        case 'values':
                            $variation['values'] = [];
                            break;
                    }
                }
            }

            // Validate values array
            if (!is_array($variation['values'])) {
                $variation['values'] = [];
            } else {
                foreach ($variation['values'] as &$val) {
                    if (!isset($val['label'])) $val['label'] = '';
                    if (!isset($val['optionPrice'])) $val['optionPrice'] = 0;
                }
            }
        }

        return $data;
    }


    private function formatAIGenerationValidationErrors(array $errors): string
    {
        $messages = [];

        foreach ($errors as $field => $message) {
            $messages[] = $message;
        }

        return 'AI failed to generate: ' . implode(' ', $messages);
    }

    public function generateTitleSuggestions(string $result)
    {
        $result = trim($result);
        $result = preg_replace('/^["`\s]+|["`\s]+$/', '', $result);
        $result = preg_replace('/^```(json)?|```$/m', '', $result);
        $data = json_decode($result, true);

        return $data;
    }

    public  function productGeneralSetConvertNamesToIds(array $data, array $resources): array
    {
        if (isset($data['category_name'])) {
            $categoryName = strtolower(trim($data['category_name']));
            if (isset($resources['categories'][$categoryName])) {
                $data['category_id'] = $resources['categories'][$categoryName];
            } else {
                $errors[] = "Invalid category name: {$data['category_name']}";
            }
        }

        if (isset($data['sub_category_name'])) {
            $subCategoryName = strtolower(trim($data['sub_category_name']));
            if (isset($resources['sub_categories'][$subCategoryName])) {
                $data['sub_category_id'] = $resources['sub_categories'][$subCategoryName];
            }
        }

        if (!empty($errors)) {
            throw new \RuntimeException($this->formatAIGenerationValidationErrors($errors));
        }

        return [
            'success' => true,
            'data' => $data
        ];
    }
}
