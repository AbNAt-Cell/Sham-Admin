<?php

namespace Modules\AI\app\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class GenerateTitleFromImageRequest extends FormRequest
{
    /**
     * Get the validation rules that apply to the request.
     */
    public function rules(): array
    {
        return [
            'image' => 'required|image|mimes:jpeg,png,jpg,gif|max:1024',
        ];
    }

    public function messages(): array{
        return [
            'image.required' => translate('Image is required for analysis.'),
            'image.image' => translate('The uploaded file must be an image.'),
            'image.mimes' => translate('Only JPEG, PNG, JPG, and GIF images are allowed.'),
            'image.max' => translate('Image size must not exceed 1MB.'),
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
