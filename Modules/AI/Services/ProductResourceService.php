<?php

namespace Modules\AI\Services;

use App\Model\AddOn;
use App\Model\Category;
use App\Models\Cuisine;

class ProductResourceService
{
    protected Category $category;
    private AddOn $addOn;
    private Cuisine $cuisine;

    public function __construct()
    {
        $this->category = new Category();
        $this->addOn = new AddOn();
        $this->cuisine = new Cuisine();
    }

    private function getCategoryEntityData($position = 0)
    {
        return $this->category
            ->where(['position' => $position])
            ->get(['id', 'name'])
            ->mapWithKeys(fn($item) => [strtolower($item->name) => $item->id])
            ->toArray();
    }

    private function getAddonEntityData()
    {
        return $this->addOn
            ->get(['id', 'name'])
            ->mapWithKeys(fn($item) => [strtolower($item->name) => $item->id])
            ->toArray();
    }

    private function getCuisineEntityData()
    {
        return $this->cuisine
            ->get(['id', 'name'])
            ->mapWithKeys(fn($item) => [strtolower($item->name) => $item->id])
            ->toArray();
    }

    public function productGeneralSetupData(): array
    {
        $data = [
            'categories' => $this->getCategoryEntityData(0),
            'sub_categories' => $this->getCategoryEntityData(1),
        ];
        return $data;
    }

    public function productAddonSetupData(): array
    {
        $data = [
            'addons' => $this->getAddonEntityData(),
        ];
        return $data;
    }

    public function productCuisineSetupData(): array
    {
        $data = [
            'cuisines' => $this->getCuisineEntityData(),
        ];
        return $data;
    }

    public function getVariationData($category_id): array
    {
        $category = Category::with('zones')->find($category_id);

        return [
            'zones' => $category
                ? $category->zones->map(fn($z) => ['id' => $z->id, 'name' => $z->name])->toArray()
                : [],
        ];
    }


}
