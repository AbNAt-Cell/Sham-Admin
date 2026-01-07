@extends('layouts.admin.app')

@section('title', translate('Update product'))

@push('css_or_js')
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <link href="{{asset('public/assets/admin/css/tags-input.min.css')}}" rel="stylesheet">

    {{--AI--}}
    <link rel="stylesheet" href="{{asset('public/assets/admin/css/ai-sidebar.css') }}"/>
@endpush

@section('content')
    <div class="content container-fluid">
        <div class="d-flex flex-wrap gap-2 align-items-center mb-4">
            <h2 class="h1 mb-0 d-flex align-items-center gap-2">
                <img width="20" class="avatar-img" src="{{asset('public/assets/admin/img/icons/product.png')}}" alt="">
                <span class="page-header-title">
                    {{translate('Product_Update')}}
                </span>
            </h2>
        </div>

        <div class="row gx-2 gx-lg-3">
            <div class="col-sm-12 col-lg-12 mb-3 mb-lg-2">
                <form action="javascript:" method="post" id="product_form" enctype="multipart/form-data">
                    @csrf
                    <div class="row g-2">
                        <div class="col-lg-6">
                            <div class="card">
                                <div class="card-body">
                                    @php($data = Helpers::get_business_settings('language'))
                                    @php($defaultLang = Helpers::get_default_language())

                                    @if($data && array_key_exists('code', $data[0]))
                                        <ul class="nav nav-tabs w-fit-content mb-4">
                                            @foreach($data as $lang)
                                                <li class="nav-item">
                                                    <a class="nav-link lang_link {{$lang['code'] == 'en'? 'active':''}}" href="#" id="{{$lang['code']}}-link">{{Helpers::get_language_name($lang['code']).'('.strtoupper($lang['code']).')'}}</a>
                                                </li>
                                            @endforeach

                                        </ul>
                                        @foreach($data as $lang)
                                            <?php
                                            if(count($product['translations'])){
                                                $translate = [];
                                                foreach($product['translations'] as $t)
                                                {
                                                    if($t->locale == $lang['code'] && $t->key=="name"){
                                                        $translate[$lang['code']]['name'] = $t->value;
                                                    }
                                                    if($t->locale == $lang['code'] && $t->key=="description"){
                                                        $translate[$lang['code']]['description'] = $t->value;
                                                    }

                                                }
                                            }
                                            ?>
                                            <div class="{{$lang['code'] != 'en'? 'd-none':''}} lang_form" id="{{$lang['code']}}-form">
                                                <div class="form-group">
                                                    <div class="d-flex justify-content-between align-items-center">
                                                        <label class="input-label" for="{{$lang['code']}}_name">{{translate('name')}} ({{strtoupper($lang['code'])}})</label>

                                                        <button type="button" class="btn bg-white text-ai bg-transparent shadow-none border-0 opacity-1 generate_btn_wrapper p-0 auto_fill_title title-btn-wrapper"
                                                                id="title-{{ $lang['code'] }}-action-btn"
                                                                data-route="{{ route('admin.product.title-auto-fill') }}"
                                                                data-lang="{{ $lang['code'] }}">
                                                            <div class="btn-svg-wrapper">
                                                                <img width="18" height="18" class="" src="{{ asset(path: 'public/assets/admin/img/ai/blink-right-small.svg') }}" alt="">
                                                            </div>
                                                            <span class="ai-text-animation d-none" role="status">{{ translate('Just_a_second') }}</span>
                                                            <span class="btn-text">{{ translate('Generate') }}</span>
                                                        </button>
                                                    </div>

                                                    <div class="outline-wrapper title-container-{{$lang['code']}}">
                                                         <input type="text" {{$lang['status'] == true ? 'required':''}} name="name[]" id="{{$lang['code']}}_name"
                                                                value="{{$translate[$lang['code']]['name']??$product['name']}}" class="form-control"
                                                                placeholder="{{translate('New Product')}}" tabindex="1">
                                                    </div>

                                                </div>
                                                <input type="hidden" name="lang[]" value="{{$lang['code']}}">
                                                <div class="form-group lang-form">
                                                    <div class="d-flex justify-content-between align-items-center">
                                                        <label class="input-label" for="{{$lang['code']}}_description">{{translate('short')}} {{translate('description')}}  ({{strtoupper($lang['code'])}})</label>

                                                        <button type="button" class="btn bg-white text-ai bg-transparent shadow-none border-0 opacity-1 generate_btn_wrapper p-0 auto_fill_short_description short-description-btn-wrapper"
                                                                id="short-description-{{ $lang['code'] }}-action-btn"  data-lang="{{ $lang['code'] }}"
                                                                data-route="{{ route('admin.product.short-description-auto-fill') }}">
                                                            <div class="btn-svg-wrapper">
                                                                <img width="18" height="18" class=""
                                                                     src="{{ asset(path: 'public/assets/admin/img/ai/blink-right-small.svg') }}" alt="">
                                                            </div>
                                                            <span class="ai-text-animation d-none" role="status">{{ translate('Just_a_second') }}</span>
                                                            <span class="btn-text">{{ translate('Generate') }}</span>
                                                        </button>
                                                    </div>

                                                    <div class="outline-wrapper">
                                                        <textarea name="description[]" class="form-control {{ $lang['code'] }}_short_description" rows="5" id="{{$lang['code']}}_hiddenArea" tabindex="2">{{$translate[$lang['code']]['description']??$product['description']}}</textarea>
                                                    </div>
                                                </div>
                                            </div>
                                        @endforeach
                                    @else
                                        <div class="card p-4" id="english-form">
                                            <div class="form-group">
                                                <div class="d-flex justify-content-between align-items-center">
                                                    <label class="input-label">{{translate('name')}} (EN)</label>

                                                    <button type="button" class="btn bg-white text-ai bg-transparent shadow-none border-0 opacity-1 generate_btn_wrapper p-0 auto_fill_title title-btn-wrapper"
                                                            id="title-en-action-btn"
                                                            data-route="{{ route('admin.product.title-auto-fill') }}"
                                                            data-lang="en">
                                                        <div class="btn-svg-wrapper">
                                                            <img width="18" height="18" class="" src="{{ asset(path: 'public/assets/admin/img/ai/blink-right-small.svg') }}" alt="">
                                                        </div>
                                                        <span class="ai-text-animation d-none" role="status">{{ translate('Just_a_second') }}</span>
                                                        <span class="btn-text">{{ translate('Generate') }}</span>
                                                    </button>
                                                </div>
                                                <div class="outline-wrapper title-container-{{$lang['code']}}">
                                                    <input type="text" name="name[]" value="{{$product['name']}}" class="form-control" placeholder="{{translate('New Product')}}" tabindex="1" required>
                                                </div>
                                            </div>
                                            <input type="hidden" name="lang[]" value="en">
                                            <div class="form-group lang-form pt-4">
                                                <div class="d-flex justify-content-between align-items-center">
                                                    <label class="input-label">{{translate('short')}} {{translate('description')}} (EN)</label>

                                                    <button type="button" class="btn bg-white text-ai bg-transparent shadow-none border-0 opacity-1 generate_btn_wrapper p-0 auto_fill_short_description short-description-btn-wrapper"
                                                            id="short-description-en-action-btn"  data-lang="en"
                                                            data-route="{{ route('admin.product.short-description-auto-fill') }}">
                                                        <div class="btn-svg-wrapper">
                                                            <img width="18" height="18" class=""
                                                                 src="{{ asset(path: 'public/assets/admin/img/ai/blink-right-small.svg') }}" alt="">
                                                        </div>
                                                        <span class="ai-text-animation d-none" role="status">{{ translate('Just_a_second') }}</span>
                                                        <span class="btn-text">{{ translate('Generate') }}</span>
                                                    </button>
                                                </div>
                                                <div class="outline-wrapper">
                                                    <textarea name="description[]" class="form-control textarea-h-100 en_short_description" id="hiddenArea" tabindex="2">{{ $product['description'] }}</textarea>
                                                </div>
                                            </div>
                                        </div>
                                    @endif
                                </div>
                            </div>
                        </div>
                        <div class="col-lg-6">
                            <div class="card h-100">
                                <div class="card-body">
                                    <div class="form-group">
                                        <label class="font-weight-bold">{{translate('product')}} {{translate('image')}}</label>
                                        <small class="text-danger">* ( {{translate('ratio')}} 1:1 )</small>

                                        <div class="d-flex justify-content-center mt-4">
                                            <div class="upload-file cmn_focus rounded">
                                                <input type="file" name="image" accept=".jpg, .png, .jpeg, .gif, .bmp, .tif, .tiff|image/*" class="upload-file__input" tabindex="3">
                                                <div class="upload-file__img_drag upload-file__img">
                                                    <img width="176" src="{{$product['imageFullPath']}}" alt="{{ translate('product') }}">
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="col-lg-6">
                            <div class="row g-2">
                                <div class="col-12">
                                    <div class="general_wrapper">
                                        <div class="outline-wrapper">
                                            <div class="card h-100 bg-animate">
                                                <div class="card-header">
                                                    <h4 class="mb-0 d-flex gap-2 align-items-center">
                                                        <i class="tio-category"></i>
                                                        {{translate('Category')}}
                                                    </h4>

                                                    <button type="button"
                                                            class="btn bg-white text-ai d-flex gap-1 mb-0 bg-transparent shadow-none border-0 opacity-1 generate_btn_wrapper p-0 general_setup_auto_fill"
                                                            id="general_setup_auto_fill"
                                                            data-route="{{ route('admin.product.general-setup-auto-fill') }}"
                                                            data-lang="en">
                                                        <div class="btn-svg-wrapper">
                                                            <img width="18" height="18" class=""
                                                                 src="{{ asset(path: 'public/assets/admin/img/ai//blink-right-small.svg') }}" alt="">
                                                        </div>
                                                        <span class="ai-text-animation d-none" role="status">{{ translate('Just_a_second') }}</span>
                                                        <span class="btn-text">{{ translate('Generate') }}</span>
                                                    </button>

                                                </div>
                                                <div class="card-body">
                                                    <div class="row">
                                                        <div class="col-sm-6">
                                                            <div class="form-group">
                                                                <label class="input-label" for="exampleFormControlSelect1">{{translate('category')}}
                                                                    <span class="text-danger">*</span></label>
                                                                <select name="category_id" id="category-id" class="form-control js-select2-custom"
                                                                        onchange="getRequest('{{url('/')}}/admin/product/get-categories?parent_id='+this.value,'sub-categories')" tabindex="4">
                                                                    @foreach($categories as $category)
                                                                        <option
                                                                            value="{{$category['id']}}" {{ $category->id==$product_category[0]->id ? 'selected' : ''}} >{{$category['name']}}</option>
                                                                    @endforeach
                                                                </select>
                                                            </div>
                                                        </div>
                                                        <div class="col-sm-6">
                                                            <div class="form-group">
                                                                <label class="input-label" for="exampleFormControlSelect1">{{translate('sub_Category')}}<span
                                                                        class="input-label-secondary"></span></label>
                                                                <select name="sub_category_id" id="sub-categories"
                                                                        data-id="{{count($product_category)>=2?$product_category[1]->id:''}}"
                                                                        class="form-control js-select2-custom"
                                                                        onchange="getRequest('{{url('/')}}/admin/product/get-categories?parent_id='+this.value,'sub-sub-categories')" tabindex="5">
                                                                </select>
                                                            </div>
                                                        </div>
                                                        <div class="col-sm-6">
                                                            <div class="form-group">
                                                                <label class="input-label" for="exampleFormControlInput1">{{translate('item_Type')}}
                                                                    <span class="text-danger">*</span>
                                                                </label>
                                                                <select name="item_type" class="form-control js-select2-custom" tabindex="6">
                                                                    <option value="0" {{$product['set_menu']==0?'selected':''}}>{{translate('product')}} {{translate('item')}}</option>
                                                                    <option value="1" {{$product['set_menu']==1?'selected':''}}>{{translate('set_menu')}}</option>
                                                                </select>
                                                            </div>
                                                        </div>
                                                        <div class="col-sm-6">
                                                            <div class="form-group">
                                                                <label class="input-label" for="product_type">
                                                                    {{translate('product_Type')}}
                                                                    <span class="text-danger">*</span>
                                                                </label>
                                                                <select name="product_type" class="form-control js-select2-custom" tabindex="7" required>
                                                                    <option value="veg" {{$product['product_type']=='veg'?'selected':''}}>{{translate('veg')}}</option>
                                                                    <option value="non_veg" {{$product['product_type']=='non_veg'?'selected':''}}>{{translate('nonveg')}}</option>
                                                                </select>
                                                            </div>
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>

                                @php($halalStatus = \App\CentralLogics\Helpers::get_business_settings('halal_tag_status') ?? 0)
                                @if($halalStatus)
                                    <div class="col-12">
                                        <div class="card">
                                            <div class="card-body">
                                                <div class="d-flex align-items-center justify-content-between gap-sm-3 gap-1 flex-sm-nowrap flex-wrap">
                                                    <div class="text-dark">{{ translate('Turn on the switch to mark this Food as Halal. A halal tag will be shown in food details, In customer app & website.') }}</div>
                                                    <div class="d-flex gap-3 align-items-center">
                                                        <h5 class="mb-0 text-nowrap">{{translate('Halal Food')}}</h5>
                                                        <label class="switcher">
                                                            <input type="hidden" name="halal_status" value="off">
                                                            <input class="switcher_input" type="checkbox" tabindex="8" {{ $product->main_branch_product?->halal_status == 1 ? "checked" : '' }} name="halal_status">
                                                            <span class="switcher_control"></span>
                                                        </label>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                @endif

                                <div class="col-12">
                                    <div class="price_wrapper">
                                        <div class="outline-wrapper">
                                            <div class="card h-100 bg-animate">
                                                <div class="card-header">
                                                    <h4 class="mb-0 d-flex gap-2 align-items-center">
                                                        <i class="tio-dollar"></i>
                                                        {{translate('Price_Information')}}
                                                    </h4>

                                                    <button type="button"
                                                            class="btn bg-white text-ai d-flex gap-1 mb-0 bg-transparent shadow-none border-0 opacity-1 price_btn_wrapper p-0 price_setup_auto_fill"
                                                            id="price_setup_auto_fill"
                                                            data-route="{{ route('admin.product.price-others-auto-fill') }}"  data-lang="en">
                                                        <div class="btn-svg-wrapper">
                                                            <img width="18" height="18" class=""
                                                                 src="{{ asset(path: 'public/assets/admin/img/ai//blink-right-small.svg') }}" alt="">
                                                        </div>
                                                        <span class="ai-text-animation d-none" role="status">{{ translate('Just_a_second') }}</span>
                                                        <span class="btn-text">{{ translate('Generate') }}</span>
                                                    </button>
                                                </div>
                                                <div class="card-body">
                                                    <div class="row">
                                                        <div class="col-12">
                                                            <div class="form-group">
                                                                <label class="input-label">{{translate('default_Price')}}
                                                                    <span class="text-danger">*</span>
                                                                </label>
                                                                <input type="number" value="{{$product['price']}}" min="0" name="price"
                                                                    class="form-control" step="0.01"
                                                                    placeholder="{{translate('Ex : 100')}}" tabindex="9" required>
                                                            </div>
                                                        </div>
                                                        <div class="col-sm-6">
                                                            <div class="form-group">
                                                                <label class="input-label">{{translate('discount_Type')}}
                                                                    <span class="text-danger">*</span></label>
                                                                <select name="discount_type" class="form-control js-select2-custom" tabindex="10">
                                                                    <option value="percent" {{$product['discount_type']=='percent'?'selected':''}}>
                                                                        {{translate('percent')}}
                                                                    </option>
                                                                    <option value="amount" {{$product['discount_type']=='amount'?'selected':''}}>
                                                                        {{translate('amount')}}
                                                                    </option>
                                                                </select>
                                                            </div>
                                                        </div>
                                                        <div class="col-sm-6">
                                                            <div class="form-group">
                                                                <label class="input-label">{{translate('discount')}}
                                                                    <span class="text-danger">*</span></label>
                                                                <input type="number" min="0" value="{{$product['discount']}}"
                                                                    name="discount" class="form-control" required
                                                                    placeholder="Ex : 100" tabindex="11">
                                                            </div>
                                                        </div>
                                                        <div class="col-sm-6">
                                                            <div class="form-group">
                                                                <label class="input-label">{{translate('tax_Type')}}
                                                                    <span class="text-danger">*</span></label>
                                                                <select name="tax_type" class="form-control js-select2-custom" tabindex="12">
                                                                    <option value="percent" {{$product['tax_type']=='percent'?'selected':''}}>{{translate('percentage')}}
                                                                    </option>
                                                                    <option value="amount" {{$product['tax_type']=='amount'?'selected':''}}>{{translate('amount')}}
                                                                    </option>
                                                                </select>
                                                            </div>
                                                        </div>
                                                        <div class="col-sm-6">
                                                            <div class="form-group">
                                                                <label class="input-label" for="exampleFormControlInput1">{{translate('tax_Rate')}}
                                                                    <span class="text-danger">*</span></label>
                                                                <input type="number" value="{{$product['tax']}}" min="0" name="tax"
                                                                    class="form-control" step="0.01"
                                                                    placeholder="{{translate('Ex : 7')}}" tabindex="13" required>
                                                            </div>
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>

                                <div class="col-12">
                                    <div class="stock_wrapper">
                                        <div class="outline-wrapper">
                                            <div class="card h-100 bg-animate">
                                                <div class="card-header">
                                                    <h4 class="mb-0 d-flex gap-2 align-items-center">
                                                        <i class="tio-dollar"></i>
                                                        {{translate('Stock Information')}}
                                                    </h4>

                                                    <button type="button"
                                                            class="btn bg-white text-ai d-flex gap-1 mb-0 bg-transparent shadow-none border-0 opacity-1 price_btn_wrapper p-0 stock_setup_auto_fill"
                                                            id="stock_setup_auto_fill"
                                                            data-route="{{ route('admin.product.stock-setup-auto-fill') }}"
                                                            data-lang="en">
                                                        <div class="btn-svg-wrapper">
                                                            <img width="18" height="18" class=""
                                                                 src="{{ asset(path: 'public/assets/admin/img/ai//blink-right-small.svg') }}" alt="">
                                                        </div>
                                                        <span class="ai-text-animation d-none" role="status">{{ translate('Just_a_second') }}</span>
                                                        <span class="btn-text">{{ translate('Generate') }}</span>
                                                    </button>
                                                </div>
                                                <div class="card-body">
                                                    <div class="row">
                                                        <div class="col-sm-6">
                                                            <div class="form-group">
                                                                <label class="input-label">{{translate('Stock Type')}}</label>
                                                                <select name="stock_type" class="form-control js-select2-custom" id="stock_type" tabindex="14">
                                                                    <option value="unlimited" {{ $product->main_branch_product?->stock_type == 'unlimited' ? 'selected' : '' }}>{{translate('unlimited')}}</option>
                                                                    <option value="daily" {{ $product->main_branch_product?->stock_type == 'daily' ? 'selected' : '' }}>{{translate('daily')}}</option>
                                                                    <option value="fixed" {{ $product->main_branch_product?->stock_type == 'fixed' ? 'selected' : '' }}>{{translate('Fixed')}}</option>
                                                                </select>
                                                            </div>
                                                        </div>
                                                        <div class="col-sm-6 d-none" id="product_stock_div">
                                                            <div class="form-group">
                                                                <label class="input-label">{{translate('Product Stock')}}
                                                                </label>
                                                                <input id="product_stock" type="number" name="product_stock" class="form-control"
                                                                      value="{{ $product->main_branch_product?->stock }}" placeholder="{{translate('Ex : 10')}}" tabindex="15">
                                                            </div>
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="col-lg-6">
                            <div class="row g-2">
                                <div class="col-12">
                                    <div class="card">
                                        <div class="card-body">
                                            <div class="d-flex align-items-center justify-content-between gap-3">
                                                <div class="text-dark">{{translate('turning visibility off will not show this product in the user app and website')}}</div>
                                                <div class="d-flex gap-3 align-items-center">
                                                    <h5>{{translate('Visibility')}}</h5>
                                                    <label class="switcher rounded-pill cmn_focus-shadow">
                                                        <input class="switcher_input" type="checkbox" name="status" tabindex="16" {{$product->status == 1? 'checked' : ''}} >
                                                        <span class="switcher_control"></span>
                                                    </label>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                <div class="col-12">
                                    <div class="card h-100">
                                        <div class="card-header">
                                            <h4 class="mb-0 d-flex gap-2 align-items-center">
                                                <i class="tio-watches"></i>
                                                {{translate('Availability')}}
                                            </h4>
                                        </div>
                                        <div class="card-body">
                                            <div class="row g-2">
                                                <div class="col-sm-6">
                                                    <div class="form-group">
                                                        <label class="input-label">{{translate('available_From')}}</label>
                                                        <input type="time" value="{{$product['available_time_starts']}}"
                                                            name="available_time_starts" class="form-control"
                                                            placeholder="{{translate('Ex : 10:30 am')}}" tabindex="17" required>
                                                    </div>
                                                </div>
                                                <div class="col-sm-6">
                                                    <div class="form-group">
                                                        <label class="input-label">{{translate('available_Till')}}</label>
                                                        <input type="time" value="{{$product['available_time_ends']}}"
                                                            name="available_time_ends" class="form-control" tabindex="18" placeholder="{{translate('5:45 pm')}}"
                                                            required>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                <div class="col-12">
                                    <div class="addon_wrapper">
                                        <div class="outline-wrapper">
                                            <div class="card h-100 bg-animate">
                                                <div class="card-header">
                                                    <h4 class="mb-0 d-flex gap-2 align-items-center">
                                                        <i class="tio-puzzle"></i>
                                                        {{translate('Addons')}}
                                                    </h4>

                                                    <button type="button"
                                                            class="btn bg-white text-ai d-flex gap-1 mb-0 bg-transparent shadow-none border-0 opacity-1 price_btn_wrapper p-0 addon_setup_auto_fill"
                                                            id="addon_setup_auto_fill"
                                                            data-route="{{ route('admin.product.addon-setup-auto-fill') }}"
                                                            data-lang="en">
                                                        <div class="btn-svg-wrapper">
                                                            <img width="18" height="18" class=""
                                                                 src="{{ asset(path: 'public/assets/admin/img/ai//blink-right-small.svg') }}" alt="">
                                                        </div>
                                                        <span class="ai-text-animation d-none" role="status">{{ translate('Just_a_second') }}</span>
                                                        <span class="btn-text">{{ translate('Generate') }}</span>
                                                    </button>

                                                </div>
                                                <div class="card-body">
                                                    <div class="form-group">
                                                        <label class="input-label">{{translate('Select_Addons')}}</label>
                                                        <select name="addon_ids[]" class="form-control cmn_focus" id="choose_addons" multiple="multiple" tabindex="19">
                                                            @foreach(\App\Model\AddOn::orderBy('name')->get() as $addon)
                                                                <option
                                                                    value="{{$addon['id']}}" {{in_array($addon->id,json_decode($product['add_ons'],true))?'selected':''}}>{{$addon['name']}}</option>
                                                            @endforeach
                                                        </select>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                <div class="col-12">
                                    <div class="tags_wrapper">
                                        <div class="outline-wrapper">
                                            <div class="card h-100 bg-animate">
                                                <div class="card-header">
                                                    <h4 class="mb-0 d-flex gap-2 align-items-center">
                                                        <i class="tio-label"></i>
                                                        {{translate('tags')}}
                                                    </h4>

                                                    <button type="button"
                                                            class="btn bg-white text-ai d-flex gap-1 mb-0 bg-transparent shadow-none border-0 opacity-1 price_btn_wrapper p-0 search_tag_setup_auto_fill"
                                                            id="search_tag_setup_auto_fill"
                                                            data-route="{{ route('admin.product.search-tag-setup-auto-fill') }}"
                                                            data-lang="en">
                                                        <div class="btn-svg-wrapper">
                                                            <img width="18" height="18" class=""
                                                                 src="{{ asset(path: 'public/assets/admin/img/ai//blink-right-small.svg') }}" alt="">
                                                        </div>
                                                        <span class="ai-text-animation d-none" role="status">{{ translate('Just_a_second') }}</span>
                                                        <span class="btn-text">{{ translate('Generate') }}</span>
                                                    </button>
                                                </div>
                                                <div class="card-body">
                                                    <div class="row g-2">
                                                        <div class="col-12">
                                                            <a href="javascript:void(0)" class="cmn_focus rounded" tabindex="20">
                                                                <label class="input-label">{{translate('search_tag')}}</label>
                                                                <input type="text" class="form-control" name="tags" placeholder="Enter tags" value="@foreach($product->tags as $c) {{$c->tag.','}} @endforeach" data-role="tagsinput">
                                                            </a>
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                <div class="col-12">
                                    <div class="card">
                                        <div class="card-body">
                                            <div class="d-flex align-items-center justify-content-between gap-3">
                                                <div class="text-dark">{{ translate('turning recommended status on will show this product in the chef recommended section in user app and website') }}</div>
                                                <div class="d-flex gap-3 align-items-center">
                                                    <h5>{{translate('Recommended')}}</h5>
                                                    <label class="switcher rounded-pill cmn_focus-shadow">
                                                        <input class="switcher_input" type="checkbox" name="is_recommended" tabindex="21" {{$product->is_recommended == 1? 'checked' : ''}} >
                                                        <span class="switcher_control"></span>
                                                    </label>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                <div class="col-12">
                                    <div class="cuisine_wrapper">
                                        <div class="outline-wrapper">
                                            <div class="card h-100 bg-animate">
                                                <div class="card-header">
                                                    <h4 class="mb-0 d-flex gap-2 align-items-center">
                                                        <i class="tio-label"></i>
                                                        {{translate('cuisine')}}
                                                    </h4>

                                                    <button type="button"
                                                            class="btn bg-white text-ai d-flex gap-1 mb-0 bg-transparent shadow-none border-0 opacity-1 price_btn_wrapper p-0 cuisine_setup_auto_fill"
                                                            id="cuisine_setup_auto_fill"
                                                            data-route="{{ route('admin.product.cuisine-setup-auto-fill') }}"
                                                            data-lang="en">
                                                        <div class="btn-svg-wrapper">
                                                            <img width="18" height="18" class=""
                                                                 src="{{ asset(path: 'public/assets/admin/img/ai//blink-right-small.svg') }}" alt="">
                                                        </div>
                                                        <span class="ai-text-animation d-none" role="status">{{ translate('Just_a_second') }}</span>
                                                        <span class="btn-text">{{ translate('Generate') }}</span>
                                                    </button>
                                                </div>
                                                <div class="card-body">
                                                    <div class="row">
                                                        <div class="col-12">
                                                            <div class="">
                                                                <label class="input-label">{{translate('select cuisine')}}</label>
                                                                <select name="cuisines[]" class="form-control js-select2-custom cmn_focus" tabindex="22" multiple>
                                                                    <option value="" disabled>---{{translate('select cuisine')}}---</option>
                                                                    @foreach($cuisines as $cuisine)
                                                                        <option value="{{$cuisine['id']}}" {{ $product->cuisines->pluck('id')->contains($cuisine['id']) ? 'selected' : '' }}>{{$cuisine['name']}}</option>

                                                                    @endforeach
                                                                </select>
                                                            </div>
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>


                    <div class="variation_wrapper mt-3">
                        <div class="outline-wrapper">
                            <div class="card bg-animate">
                                <div class="card-header">
                                    <h4 class="mb-0 d-flex gap-2 align-items-center">
                                        <i class="tio-canvas-text"></i>
                                        {{ translate('Product_Variations') }}
                                    </h4>

                                    <button type="button"
                                            class="btn bg-white text-ai d-flex gap-1 mb-0 bg-transparent shadow-none border-0 opacity-1 price_btn_wrapper p-0 variation_setup_auto_fill"
                                            id="variation_setup_auto_fill"
                                            data-route="{{ route('admin.product.variation-setup-auto-fill') }}"
                                            data-lang="en">
                                        <div class="btn-svg-wrapper">
                                            <img width="18" height="18" class=""
                                                 src="{{ asset(path: 'public/assets/admin/img/ai//blink-right-small.svg') }}" alt="">
                                        </div>
                                        <span class="ai-text-animation d-none" role="status">{{ translate('Just_a_second') }}</span>
                                        <span class="btn-text">{{ translate('Generate') }}</span>
                                    </button>
                                </div>
                                <div class="card-body">
                                    <div class="row g-2">
                                        <div class="col-md-12" >
                                            <div id="add_new_option">
                                                @if (isset($product->variations))
                                                    @foreach (json_decode($product->variations,true) as $key_choice_options=>$item)
                                                        @if (isset($item["price"]))
                                                            @break
                                                        @else
                                                            @include('admin-views.product.partials._new_variations',['item'=>$item,'key'=>$key_choice_options+1])
                                                        @endif
                                                    @endforeach
                                                @endif
                                            </div>
                                        </div>
                                        <div class="mt-2">
                                            <button type="button" class="btn btn-outline-success cmn_focus" tabindex="23" id="add_new_option_button">{{translate('Add_New_Variation')}}</button>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="d-flex justify-content-end gap-3 mt-4">
                        <button type="reset" class="btn btn-secondary cmn_focus" tabindex="24">{{translate('reset')}}</button>
                        <button type="submit" class="btn btn-primary cmn_focus" tabindex="25">{{translate('update')}}</button>
                    </div>
                </form>
            </div>
        </div>

        @include('admin-views.product.partials.ai-sidebar')

        {{--AI assistant--}}
        <div class="floating-ai-button">
            <button type="button" class="btn btn-lg rounded-circle shadow-lg position-relative" data-toggle="modal" data-target="#aiAssistantModal"
                    data-action="main" title="AI Assistant">
                <span class="ai-btn-animation">
                    <span class="gradientCirc"></span>
                </span>
                <span class="position-relative z-1 text-white d-flex flex-column gap-1 align-items-center">
                    <img width="16" height="17" src="{{ asset(path: 'public/assets/admin/img/ai/hexa-ai.svg') }}" alt="">
                    <span class="fz-12 font-weight-semibold">{{ translate('Use_AI') }}</span>
                </span>
            </button>
            <div class="ai-tooltip">
                <span>{{translate("AI_Assistant")}}</span>
            </div>
        </div>
    </div>

@endsection

@push('script')

@endpush

@push('script_2')
    <script src="{{asset('public/assets/admin/js/spartan-multi-image-picker.js')}}"></script>

    {{--AI--}}
    <script src="{{ asset('public/assets/admin/js/AI/products/ai-sidebar.js') }}"></script>
    <script src="{{ asset('public/assets/admin/js/AI/products/product-title-autofill.js') }}"></script>
    <script src="{{ asset('public/assets/admin/js/AI/products/product-short-description-autofill.js') }}"></script>
    <script src="{{ asset('public/assets/admin/js/AI/products/general-setup.js') }}"></script>
    <script src="{{ asset('public/assets/admin/js/AI/products/price-setup.js') }}"></script>
    <script src="{{ asset('public/assets/admin/js/AI/products/stock-setup.js') }}"></script>
    <script src="{{ asset('public/assets/admin/js/AI/products/addon-setup.js') }}"></script>
    <script src="{{ asset('public/assets/admin/js/AI/products/cuisine-setup.js') }}"></script>
    <script src="{{ asset('public/assets/admin/js/AI/products/search-tag-setup.js') }}"></script>
    <script src="{{ asset('public/assets/admin/js/AI/products/variation-setup.js') }}"></script>
    <script src="{{ asset('public/assets/admin/js/AI/image-compressor/image-compressor.js') }}"></script>
    <script src="{{ asset('public/assets/admin/js/AI/image-compressor/compressor.min.js') }}"></script>

    <script>
        //Select 2
        $("#choose_addons").select2({
            placeholder: "Select Addons",
            allowClear: true
        });
       /* $("#choice_attributes").select2({
            placeholder: "Select Attributes",
            allowClear: true
        });*/
    </script>

    <script>
        function readURL(input) {
            if (input.files && input.files[0]) {
                var reader = new FileReader();

                reader.onload = function (e) {
                    $('#viewer').attr('src', e.target.result);
                }

                reader.readAsDataURL(input.files[0]);
            }
        }

        $("#customFileEg1").change(function () {
            readURL(this);
            $('#image-viewer-section').show(1000)
        });
    </script>

    <script>
        $(".lang_link").click(function(e){
            e.preventDefault();
            $(".lang_link").removeClass('active');
            $(".lang_form").addClass('d-none');
            $(this).addClass('active');

            let form_id = this.id;
            let lang = form_id.split("-")[0];
            console.log(lang);
            $("#"+lang+"-form").removeClass('d-none');
            if(lang == 'en')
            {
                $("#from_part_2").removeClass('d-none');
            }
            else
            {
                $("#from_part_2").addClass('d-none');
            }
        })
    </script>
    <script type="text/javascript">
        $(function () {
            $("#coba").spartanMultiImagePicker({
                fieldName: 'images[]',
                maxCount: 4,
                rowHeight: '215px',
                groupClassName: 'col-3',
                maxFileSize: '',
                placeholderImage: {
                    image: '{{asset('public/assets/admin/img/400x400/img2.jpg')}}',
                    width: '100%'
                },
                dropFileLabel: "Drop Here",
                onAddRow: function (index, file) {

                },
                onRenderedPreview: function (index) {

                },
                onRemoveRow: function (index) {

                },
                onExtensionErr: function (index, file) {
                    toastr.error('{{translate("Please only input png or jpg type file")}}', {
                        CloseButton: true,
                        ProgressBar: true
                    });
                },
                onSizeErr: function (index, file) {
                    toastr.error('{{translate("File size too big")}}', {
                        CloseButton: true,
                        ProgressBar: true
                    });
                }
            });
        });
    </script>

    <script>
        function getRequest(route, id) {
            $.get({
                url: route,
                dataType: 'json',
                success: function (data) {
                    $('#' + id).empty().append(data.options);
                },
            });
        }

        $(document).ready(function () {
            setTimeout(function () {
                let category = $("#category-id").val();
                let sub_category = '{{count($product_category)>=2?$product_category[1]->id:''}}';
                let sub_sub_category = '{{count($product_category)>=3?$product_category[2]->id:''}}';
                getRequest('{{url('/')}}/admin/product/get-categories?parent_id=' + category + '&&sub_category=' + sub_category, 'sub-categories');
                getRequest('{{url('/')}}/admin/product/get-categories?parent_id=' + sub_category + '&&sub_category=' + sub_sub_category, 'sub-sub-categories');
            }, 1000)
        });
    </script>

    <script>
        $(document).on('ready', function () {
            $('.js-select2-custom').each(function () {
                var select2 = $.HSCore.components.HSSelect2.init($(this));
            });
        });
    </script>

    <script src="{{asset('public/assets/admin')}}/js/tags-input.min.js"></script>

    <script>
        function show_min_max(data){
            $('#min_max1_'+data).removeAttr("readonly");
            $('#min_max2_'+data).removeAttr("readonly");
            $('#min_max1_'+data).attr("required","true");
            $('#min_max2_'+data).attr("required","true");
        }
        function hide_min_max (data){
            $('#min_max1_'+data).val(null).trigger('change');
            $('#min_max2_'+data).val(null).trigger('change');
            $('#min_max1_'+data).attr("readonly","true");
            $('#min_max2_'+data).attr("readonly","true");
            $('#min_max1_'+data).attr("required","false");
            $('#min_max2_'+data).attr("required","false");
        }

        var count= {{isset($product->variations)?count(json_decode($product->variations,true)):0}};

        $(document).ready(function(){
            console.log(count);

            $("#add_new_option_button").click(function(e){
                count++;
                var add_option_view = `
        <div class="card view_new_option mb-2" >
            <div class="card-header">
                <label for="" id=new_option_name_`+count+`> {{  translate('add new variation')}}</label>
            </div>
            <div class="card-body">
                <div class="row g-2">
                    <div class="col-lg-3 col-md-6">
                        <label for="">{{ translate('name')}}</label>
                        <input required name=options[`+count+`][name] class="form-control" type="text" onkeyup="new_option_name(this.value,`+count+`)">
                    </div>

                    <div class="col-lg-3 col-md-6">
                        <div class="form-group">
                            <label class="input-label text-capitalize d-flex alig-items-center"><span class="line--limit-1">{{ translate('messages.selcetion_type') }} </span>
                            </label>
                            <div class="resturant-type-group border">
                                <label class="form-check form--check mr-2 mr-md-4">
                                    <input class="form-check-input" type="radio" value="multi"
                                    name="options[`+count+`][type]" id="type`+count+`" checked onchange="show_min_max(`+count+`)"
                                    >
                                    <span class="form-check-label">
                                        {{ translate('Multiple') }}
                    </span>
                </label>

                <label class="form-check form--check mr-2 mr-md-4">
                    <input class="form-check-input" type="radio" value="single"
                    name="options[`+count+`][type]" id="type`+count+`" onchange="hide_min_max(`+count+`)"
                                    >
                                    <span class="form-check-label">
                                        {{ translate('Single') }}
                    </span>
                </label>
            </div>
        </div>
    </div>
    <div class="col-12 col-lg-6">
        <div class="row g-2">
            <div class="col-sm-6 col-md-4">
                <label for="">{{  translate('Min')}}</label>
                                <input id="min_max1_`+count+`" required name="options[`+count+`][min]" class="form-control" type="number" min="1">
                            </div>
                            <div class="col-sm-6 col-md-4">
                                <label for="">{{  translate('Max')}}</label>
                                <input id="min_max2_`+count+`" required name="options[`+count+`][max]" class="form-control" type="number" min="1">
                            </div>

                            <div class="col-md-4">
                                <label class="d-md-block d-none">&nbsp;</label>
                                    <div class="d-flex align-items-center justify-content-between">
                                    <div>
                                        <input id="options[`+count+`][required]" name="options[`+count+`][required]" type="checkbox">
                                        <label for="options[`+count+`][required]" class="m-0">{{  translate('Required')}}</label>
                                    </div>
                                    <div>
                                        <button type="button" class="btn btn-danger btn-sm delete_input_button" onclick="removeOption(this)"
                                            title="{{  translate('Delete')}}">
                                            <i class="tio-add-to-trash"></i>
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>





            <div id="option_price_` + count + `" >
                    <div class="border rounded p-3 pb-0 mt-3">
                        <div  id="option_price_view_` + count + `">
                            <div class="row g-3 add_new_view_row_class mb-3">
                                <div class="col-md-4 col-sm-6">
                                    <label for="">{{ translate('Option_name') }}</label>
                                    <input class="form-control" required type="text" name="options[` + count +`][values][0][label]" id="">
                                </div>
                                <div class="col-md-4 col-sm-6">
                                    <label for="">{{ translate('Additional_price') }}</label>
                                    <input class="form-control" required type="number" min="0" step="0.01" name="options[` + count + `][values][0][optionPrice]" id="">
                                </div>
                            </div>
                        </div>
                        <div class="row mt-3 p-3 mr-1 d-flex "  id="add_new_button_` + count + `">
                            <button type="button" class="btn btn-outline-primary cmn_focus" onclick="add_new_row_button(` +
                    count + `)" >{{ translate('Add_New_Option') }}</button>
                        </div>
                    </div>
                </div>
            </div>
        </div>`;
                $("#add_new_option").append(add_option_view);

            });

        });

        function new_option_name(value,data)
        {
            $("#new_option_name_"+data).empty();
            $("#new_option_name_"+data).text(value)
            console.log(value);
        }
        function removeOption(e)
        {
            element = $(e);
            element.parents('.view_new_option').remove();
        }
        function deleteRow(e)
        {
            element = $(e);
            element.parents('.add_new_view_row_class').remove();
        }


        function add_new_row_button(data)
        {
            count = data;
            countRow = 1 + $('#option_price_view_'+data).children('.add_new_view_row_class').length;
            var add_new_row_view = `
                <div class="row add_new_view_row_class mb-3 position-relative pt-3 pt-md-0">
                    <div class="col-md-4 col-sm-5">
                            <label for="">{{translate('Option_name')}}</label>
                            <input class="form-control" required type="text" name="options[`+count+`][values][`+countRow+`][label]" id="">
                        </div>
                        <div class="col-md-4 col-sm-5">
                            <label for="">{{translate('Additional_price')}}</label>
                            <input class="form-control"  required type="number" min="0" step="0.01" name="options[`+count+`][values][`+countRow+`][optionPrice]" id="">
                        </div>
                        <div class="col-sm-2 max-sm-absolute">
                            <label class="d-none d-md-block">&nbsp;</label>
                            <div class="mt-1">
                                <button type="button" class="btn btn-danger btn-sm" onclick="deleteRow(this)"
                                    title="{{translate('Delete')}}">
                                    <i class="tio-add-to-trash"></i>
                                </button>
                            </div>
                    </div>
                </div>`;
            $('#option_price_view_'+data).append(add_new_row_view);

        }

    </script>

    <script>

        $('#product_form').on('submit', function () {
            var formData = new FormData(this);

            $.ajaxSetup({
                headers: {
                    'X-CSRF-TOKEN': $('meta[name="csrf-token"]').attr('content')
                }
            });
            $.post({
                url: '{{route('admin.product.update',[$product['id']])}}',
                // data: $('#product_form').serialize(),
                data: formData,
                cache: false,
                contentType: false,
                processData: false,
                success: function (data) {
                    if (data.errors) {
                        for (var i = 0; i < data.errors.length; i++) {
                            toastr.error(data.errors[i].message, {
                                CloseButton: true,
                                ProgressBar: true
                            });
                        }
                    } else {
                        toastr.success('{{translate("product updated successfully!")}}', {
                            CloseButton: true,
                            ProgressBar: true
                        });
                        setTimeout(function () {
                            location.href = '{{route('admin.product.list')}}';
                        }, 2000);
                    }
                }
            });
        });

        @if($product->main_branch_product?->stock_type == 'daily' || $product->main_branch_product?->stock_type == 'fixed')
            $("#product_stock_div").removeClass('d-none')
        @endif

        $("#stock_type").change(function(){
            if(this.value === 'daily' || this.value === 'fixed') {
                $("#product_stock_div").removeClass('d-none')
            }
            else {
                $("#product_stock_div").addClass('d-none')
            }
        });
    </script>
@endpush
