<?php

namespace App\Http\Controllers\Api\V1;

use App\CentralLogics\CategoryLogic;
use App\CentralLogics\Helpers;
use App\Http\Controllers\Controller;
use App\Model\Category;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

class CategoryController extends Controller
{
    public function __construct(
        private Category $category,
    )
    {}


    public function getCategories(Request $request)
    {
        $limit = $request->input('limit', 10);
        $offset = $request->input('offset', 1);
        $search = $request->input('name', '');

        $categories = $this->category
            ->with('childes', 'translations')
            ->where('position', 0)
            ->where('status', 1)
            ->when($search, function ($query) use ($search) {
                $query->where('name', 'like', '%' . $search . '%');
            })
            ->orderBy('priority', 'ASC')
            ->paginate($limit, ['*'], 'page', $offset);

        return response()->json([
            'total_size' => $categories->total(),
            'limit' => $limit,
            'offset' => $offset,
            'categories' => $categories->items(),
        ], 200);
    }

    /**
     * @param $id
     * @return JsonResponse
     */
    public function getChildes($id): JsonResponse
    {
        $categories = $this->category->where(['parent_id' => $id, 'status' => 1])->get();
        return response()->json($categories, 200);
    }

    /**
     * @param $id
     * @param Request $request
     * @return JsonResponse
     */
    public function getProducts($id, Request $request): JsonResponse
    {
        $productType = $request['product_type'];
        $name = $request['name'];
        $products = CategoryLogic::products(category_id: $id, type: $productType, name: $name, limit: $request['limit'], offset: $request['offset']);
        $products['products'] = Helpers::product_data_formatting($products['products'], true);
        return response()->json($products, 200);
    }

    /**
     * @param $id
     * @return JsonResponse
     */
    public function getAllProducts($id): JsonResponse
    {
        return response()->json(Helpers::product_data_formatting(CategoryLogic::all_products($id), true), 200);
    }
}
