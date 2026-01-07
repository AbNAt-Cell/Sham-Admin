<?php

namespace Modules\AI\app\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class ProductShortDescriptionAutoFillRequest extends FormRequest
{
    /**
     * Get the validation rules that apply to the request.
     */
    public function rules(): array
    {
        return [
            'name' => 'required|string|max:255',
            'langCode' => 'nullable|string|max:20',
        ];
    }

    public function messages(): array{
        return ['name.required' => translate('name_is_required_to_generate_description')];
    }
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        return true;
    }
}
