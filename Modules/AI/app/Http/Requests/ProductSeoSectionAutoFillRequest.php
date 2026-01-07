<?php

namespace Modules\AI\app\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class ProductSeoSectionAutoFillRequest extends FormRequest
{
    /**
     * Get the validation rules that apply to the request.
     */
    public function rules(): array
    {
        return [
            'name' => 'required|string|max:255',
            'description' => 'nullable|string',
        ];
    }
    public  function messages(): array{
        return [
            'name.required' => translate('product_name_is_required_to_generate_seo_information'),
            'description.required' => translate('product_description_is_required_to_generate_seo_information'),
        ];
    }
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        return true;
    }
}
