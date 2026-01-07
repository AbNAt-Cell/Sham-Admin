<?php

namespace Modules\AI\app\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class GeneralSetupRequest extends FormRequest
{
    /**
     * Get the validation rules that apply to the request.
     */
    public function rules(): array
    {
        return [
            'name' => 'required|string|max:255',
            'description' => 'required|string',
        ];
    }

    public function messages(): array{
        return [
            'name.required' => translate('name_is_required_to_category_setup'),
            'description.required' => translate('short_description_is_required_to_category_setup'),
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
