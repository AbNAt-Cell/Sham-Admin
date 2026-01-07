@extends('layouts.admin.app')
@section('title', translate('Add new product'))

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
                    {{translate('Add_New_Product')}}
                </span>
            </h2>
        </div>

        <div class="row g-3">
            <div class="col-12">
                <form action="javascript:" method="post" id="product_form" enctype="multipart/form-data">
                    @csrf
                    <div class="row g-2 service-description-wrapper">
                        <div class="col-lg-6">
                            <div class="card card-body h-100">
                                @php($data = Helpers::get_business_settings('language'))
                                @php($defaultLang = Helpers::get_default_language())

                                @if($data && array_key_exists('code', $data[0]))
                                    <ul class="nav nav-tabs mb-4">

                                        @foreach($data as $lang)
                                            <li class="nav-item">
                                                <a class="nav-link lang_link {{$lang['default'] == true ? 'active':''}}" href="#" id="{{$lang['code']}}-link">{{Helpers::get_language_name($lang['code']).'('.strtoupper($lang['code']).')'}}</a>
                                            </li>
                                        @endforeach

                                    </ul>
                                    @foreach($data as $lang)
                                        <div class="{{$lang['default'] == false ? 'd-none':''}} lang_form" id="{{$lang['code']}}-form">
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
                                                    <input type="text" name="name[]" id="{{$lang['code']}}_name" class="form-control"
                                                           placeholder="{{translate('New Product')}}" {{$lang['status'] == true ? 'required':''}}
                                                           @if($lang['status'] == true) oninvalid="document.getElementById('{{$lang['code']}}-link').click()" tabindex="1" @endif>
                                                </div>
                                            </div>

                                            <input type="hidden" name="lang[]" value="{{$lang['code']}}">

                                            <div class="form-group lang-form">
                                                <div class="d-flex justify-content-between align-items-center">
                                                    <label class="input-label"
                                                       for="{{$lang['code']}}_description">{{translate('short')}} {{translate('description')}}  ({{strtoupper($lang['code'])}})</label>
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
                                                    <textarea name="description[]" class="form-control {{ $lang['code'] }}_short_description" id="{{$lang['code']}}_hiddenArea" rows="5" tabindex="2"></textarea>
                                                </div>
                                            </div>
                                        </div>
                                    @endforeach
                                @else
                                    <div class="" id="{{$defaultLang}}-form">
                                        <div class="form-group">
                                            <div class="d-flex justify-content-between align-items-center">
                                                <label class="input-label" for="exampleFormControlInput1">{{translate('name')}} (EN)</label>
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

                                            <input type="text" name="name[]" class="form-control" id="en_name" placeholder="{{translate('New Product')}}" tabindex="1" required>
                                        </div>
                                        <input type="hidden" name="lang[]" value="en">
                                        <div class="form-group">
                                            <div class="d-flex justify-content-between align-items-center">
                                                <label class="input-label"
                                                       for="exampleFormControlInput1">{{translate('short')}} {{translate('description')}} (EN)</label>

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
                                            <textarea name="description[]" class="form-control textarea-h-100 en_short_description" id="hiddenArea" tabindex="2"></textarea>
                                        </div>
                                    </div>
                                @endif
                            </div>
                        </div>
                        <div class="col-lg-6">
                            <div class="card card-body h-100">
                                <div class="form-group">
                                    <label class="font-weight-bold text-dark">{{translate('product_Image')}}</label>
                                    <small class="text-danger">* ( {{translate('ratio')}} 1:1 )</small>
                                    <div class="d-flex justify-content-center mt-4">
                                        <div class="upload-file cmn_focus rounded">
                                            <input type="file" name="image" accept=".jpg, .png, .jpeg, .gif, .bmp, .tif, .tiff|image/*" class="upload-file__input" tabindex="3">
                                            <div class="upload-file__img_drag upload-file__img">
                                                <img width="176" src="{{asset('public/assets/admin/img/icons/upload_img.png')}}" alt="">
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
                                                                <label class="input-label" for="exampleFormControlSelect1">
                                                                    {{translate('category')}}
                                                                    <span class="text-danger">*</span>
                                                                </label>
                                                                <select name="category_id" class="form-control js-select2-custom" id="category-id"
                                                                        onchange="getRequest('{{url('/')}}/admin/product/get-categories?parent_id='+this.value,'sub-categories')" tabindex="4">
                                                                    <option selected disabled>---{{translate('select')}}---</option>
                                                                    @foreach($categories as $category)
                                                                        <option value="{{$category['id']}}">{{$category['name']}}</option>
                                                                    @endforeach
                                                                </select>
                                                            </div>
                                                        </div>
                                                        <div class="col-sm-6">
                                                            <div class="form-group">
                                                                <label class="input-label" for="exampleFormControlSelect1">{{translate('sub_category')}}<span
                                                                        class="input-label-secondary"></span></label>
                                                                <select name="sub_category_id" id="sub-categories"
                                                                        class="form-control js-select2-custom"
                                                                        onchange="getRequest('{{url('/')}}/admin/product/get-categories?parent_id='+this.value,'sub-sub-categories')" tabindex="5">
                                                                    <option selected disabled>---{{translate('select')}}---</option>
                                                                </select>
                                                            </div>
                                                        </div>
                                                        <div class="col-sm-6">
                                                            <div class="form-group">
                                                                <label class="input-label" for="exampleFormControlInput1">
                                                                    {{translate('item_Type')}}
                                                                    <span class="text-danger">*</span>
                                                                </label>

                                                                <select name="item_type" class="form-control js-select2-custom" tabindex="6">
                                                                    <option selected disabled>---{{translate('select')}}---</option>
                                                                    <option value="0">{{translate('product')}} {{translate('item')}}</option>
                                                                    <option value="1">{{translate('set_menu')}}</option>
                                                                </select>
                                                            </div>
                                                        </div>
                                                        <div class="col-sm-6">
                                                            <div class="form-group">
                                                                <label class="input-label">
                                                                    {{translate('product_Type')}}
                                                                    <span class="text-danger">*</span>
                                                                </label>
                                                                <select name="product_type" class="form-control js-select2-custom" tabindex="7">
                                                                    <option selected disabled>---{{translate('select')}}---</option>
                                                                    <option value="veg">{{translate('veg')}}</option>
                                                                    <option value="non_veg">{{translate('nonveg')}}</option>
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
                                                            <input class="switcher_input" type="checkbox" checked="checked" name="halal_status" tabindex="8">
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
                                                            class="btn bg-white text-ai d-flex gap-1 mb-0 bg-transparent shadow-none border-0 opacity-1 generate_btn_wrapper price_btn_wrapper p-0 price_setup_auto_fill"
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
                                                                    <span class="text-danger">*</span></label>
                                                                <input type="number" min="0" step="any" value="1" name="price" class="form-control"
                                                                       placeholder="{{translate('Ex : 100')}}" tabindex="9" required>
                                                            </div>
                                                        </div>
                                                        <div class="col-sm-6">
                                                            <div class="form-group">
                                                                <label class="input-label">{{translate('discount_Type')}}
                                                                    <span class="text-danger">*</span>
                                                                </label>
                                                                <select name="discount_type" class="form-control js-select2-custom" id="discount_type" tabindex="10">
                                                                    <option selected disabled>---{{translate('select')}}---</option>
                                                                    <option value="percent">{{translate('percentage')}}</option>
                                                                    <option value="amount">{{translate('amount')}}</option>
                                                                </select>
                                                            </div>
                                                        </div>
                                                        <div class="col-sm-6">
                                                            <div class="form-group">
                                                                <label class="input-label"><span id="discount_label">{{translate('discount')}}</span>
                                                                    <span class="text-danger">*</span>
                                                                </label>
                                                                <input id="discount_input" type="number" min="0" name="discount" class="form-control"
                                                                       placeholder="{{translate('Ex : 5%')}}" tabindex="11" required>
                                                            </div>
                                                        </div>
                                                        <div class="col-sm-6">
                                                            <div class="form-group mb-0 pb-2">
                                                                <label class="input-label">{{translate('tax_Type')}}
                                                                    <span class="text-danger">*</span>
                                                                </label>
                                                                <select name="tax_type" class="form-control js-select2-custom" id="tax_type" tabindex="12">
                                                                    <option selected disabled>---{{translate('select')}}---</option>
                                                                    <option value="percent">{{translate('percentage')}}</option>
                                                                    <option value="amount">{{translate('amount')}}</option>
                                                                </select>
                                                            </div>
                                                        </div>
                                                        <div class="col-sm-6">
                                                            <div class="form-group mb-0 pb-2">
                                                                <label class="input-label" for="exampleFormControlInput1"><span id="tax_label">{{translate('tax_Rate')}}</span>
                                                                    <span class="text-danger">*</span>
                                                                </label>
                                                                <input id="tax_input" type="number" min="0" step="any" name="tax" class="form-control"
                                                                       placeholder="{{translate('Ex : $100')}}" tabindex="13" required>
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
                                                            class="btn bg-white text-ai d-flex gap-1 mb-0 bg-transparent shadow-none border-0 opacity-1 generate_btn_wrapper price_btn_wrapper p-0 stock_setup_auto_fill"
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
                                                            <div class="form-group mb-0">
                                                                <label class="input-label">{{translate('Stock Type')}}</label>
                                                                <select name="stock_type" class="form-control js-select2-custom" id="stock_type" tabindex="14">
                                                                    <option value="unlimited">{{translate('unlimited')}}</option>
                                                                    <option value="daily">{{translate('daily')}}</option>
                                                                    <option value="fixed">{{translate('fixed')}}</option>
                                                                </select>
                                                            </div>
                                                        </div>
                                                        <div class="col-sm-6 d-none" id="product_stock_div">
                                                            <div class="form-group">
                                                                <label class="input-label">{{translate('Product Stock')}}
                                                                </label>
                                                                <input id="product_stock" type="number" name="product_stock" class="form-control"
                                                                       placeholder="{{translate('Ex : 10')}}" tabindex="15">
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
                                            <div class="d-flex align-items-center justify-content-between gap-sm-3 gap-1 flex-sm-nowrap flex-wrap">
                                                <div class="text-dark">{{ translate('turning visibility off will not show this product in the user app and website') }}</div>
                                                <div class="d-flex gap-3 align-items-center">
                                                    <h5 class="mb-0">{{translate('Visibility')}}</h5>
                                                    <label class="switcher rounded-pill cmn_focus-shadow">
                                                        <input class="switcher_input" type="checkbox" checked="checked" name="status" tabindex="16">
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
                                                        <input type="time" name="available_time_starts" class="form-control" value="10:30:00"
                                                               placeholder="{{translate('Ex : 10:30 am')}}" tabindex="17" required>
                                                    </div>
                                                </div>
                                                <div class="col-sm-6">
                                                    <div class="form-group">
                                                        <label class="input-label">{{translate('available_Till')}}</label>
                                                        <input type="time" name="available_time_ends" class="form-control" value="19:30:00" placeholder="{{translate('5:45 pm')}}" tabindex="18" required>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                <div class="col-12 addon_wrapper">
                                    <div class="outline-wrapper">
                                        <div class="card h-100 bg-animate">
                                            <div class="card-header">
                                                <h4 class="mb-0 d-flex gap-2 align-items-center">
                                                    <i class="tio-puzzle"></i>
                                                    {{translate('Addons')}}
                                                </h4>

                                                <button type="button"
                                                        class="btn bg-white text-ai d-flex gap-1 mb-0 bg-transparent shadow-none border-0 opacity-1 generate_btn_wrapper price_btn_wrapper p-0 addon_setup_auto_fill"
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
                                                            <option value="{{$addon['id']}}">{{$addon['name']}}</option>
                                                        @endforeach
                                                    </select>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                <div class="col-12 tags_wrapper">
                                    <div class="outline-wrapper">
                                        <div class="card h-100 bg-animate">
                                            <div class="card-header">
                                                <h4 class="mb-0 d-flex gap-2 align-items-center">
                                                    <i class="tio-label"></i>
                                                    {{translate('tags')}}
                                                </h4>

                                                <button type="button"
                                                        class="btn bg-white text-ai d-flex gap-1 mb-0 bg-transparent shadow-none border-0 opacity-1 generate_btn_wrapper price_btn_wrapper p-0 search_tag_setup_auto_fill"
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
                                                <div class="row">
                                                    <div class="col-12">
                                                        <a href="javascript:void(0)" class="cmn_focus rounded" tabindex="20">
                                                            <label class="input-label">{{translate('search_tag')}}</label>
                                                            <input type="text" class="form-control" name="tags" placeholder="Enter tags" data-role="tagsinput">
                                                        </a>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                <div class="col-12">
                                    <div class="card">
                                        <div class="card-body">
                                            <div class="d-flex align-items-center justify-content-between gap-sm-3 gap-1 flex-sm-nowrap flex-wrap">
                                                <div class="text-dark">{{ translate('turning recommended status on will show this product in the chef recommended section in user app and website') }}</div>
                                                <div class="d-flex gap-3 align-items-center">
                                                    <h5>{{translate('Recommended')}}</h5>
                                                    <label class="switcher rounded-pill cmn_focus-shadow">
                                                        <input class="switcher_input" type="checkbox" checked="checked" name="is_recommended" tabindex="21">
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
                                                            class="btn bg-white text-ai d-flex gap-1 mb-0 bg-transparent shadow-none border-0 opacity-1 generate_btn_wrapper price_btn_wrapper p-0 cuisine_setup_auto_fill"
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
                                                                <select name="cuisines[]" class="form-control cmn_focus js-select2-custom" tabindex="22" multiple>
                                                                    <option value="" disabled>---{{translate('select cuisine')}}---</option>
                                                                    @foreach($cuisines as $cuisine)
                                                                        <option value="{{$cuisine['id']}}">{{$cuisine['name']}}</option>
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
                                        {{ translate('product_Variations') }}
                                    </h4>

                                    <button type="button"
                                            class="btn bg-white text-ai d-flex gap-1 mb-0 bg-transparent shadow-none border-0 opacity-1 generate_btn_wrapper price_btn_wrapper p-0 variation_setup_auto_fill"
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
                                <div class="card-body pb-0">
                                    <div class="row">
                                        <div class="col-md-12">
                                            <div id="add_new_option">
                                            </div>
                                            <br>
                                            <div class="">
                                                <a class="btn cmn_focus btn-outline-success"
                                                   id="add_new_option_button" tabindex="23">{{ translate('add_New_Variation') }}</a>
                                            </div>
                                            <br><br>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>


                    <div class="d-flex justify-content-end gap-3 mt-4">
                        <button type="reset" class="btn btn-secondary cmn_focus" tabindex="24">{{translate('reset')}}</button>
                        <button type="submit" class="btn btn-primary cmn_focus" tabindex="25">{{translate('submit')}}</button>
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
        var count = 0;
        $(document).ready(function() {

            $("#add_new_option_button").click(function(e) {
                count++;
                var add_option_view = `
                    <div class="card view_new_option mb-2" >
                        <div class="card-header">
                            <label for="" id=new_option_name_` + count + `> {{ translate('add_new') }}</label>
                        </div>
                        <div class="card-body">
                            <div class="row g-2">
                                <div class="col-lg-3 col-md-6">
                                    <label for="">{{ translate('name') }}</label>
                                    <input required name=options[` + count + `][name] class="form-control" type="text"
                                        onkeyup="new_option_name(this.value,` + count + `)">
                                </div>

                                <div class="col-lg-3 col-md-6">
                                    <div class="form-group">
                                        <label class="input-label text-capitalize d-flex alig-items-center"><span class="line--limit-1">{{ translate('selcetion_type') }} </span></label>
                                        <div class="resturant-type-group border cmn_focus">
                                            <label class="form-check form--check mr-2 mr-md-4">
                                                <input class="form-check-input" type="radio" value="multi "name="options[` + count + `][type]" id="type` + count +
                                                    `" checked onchange="show_min_max(` + count + `)">
                                                <span class="form-check-label">{{ translate('Multiple') }}</span>
                                            </label>

                                            <label class="form-check form--check mr-2 mr-md-4">
                                                <input class="form-check-input" type="radio" value="single" name="options[` + count + `][type]" id="type` + count +
                                                    `" onchange="hide_min_max(` + count + `)" >
                                                <span class="form-check-label">{{ translate('Single') }}</span>
                                            </label>
                                        </div>
                                    </div>
                                </div>
                                <div class="col-12 col-lg-6">
                                    <div class="row g-2">
                                        <div class="col-sm-6 col-md-4">
                                            <label for="">{{ translate('Min') }}</label>
                                            <input id="min_max1_` + count + `" required  name="options[` + count + `][min]" class="form-control" type="number" min="1">
                                        </div>
                                        <div class="col-sm-6 col-md-4">
                                            <label for="">{{ translate('Max') }}</label>
                                            <input id="min_max2_` + count + `"   required name="options[` + count + `][max]" class="form-control" type="number" min="1">
                                        </div>

                                        <div class="col-md-4">
                                            <label class="d-md-block d-none">&nbsp;</label>
                                        <div class="d-flex align-items-center justify-content-between">
                                        <div>
                                            <input id="options[` + count + `][required]" name="options[` + count + `][required]" type="checkbox">
                                            <label for="options[` + count + `][required]" class="m-0">{{ translate('Required') }}</label>
                                        </div>
                                        <div>
                                            <button type="button" class="btn btn-danger btn-sm delete_input_button" onclick="removeOption(this)"title="{{ translate('Delete') }}">
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
                                    count + `)" >{{ translate('Add_New_Option') }}
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>`;

            $("#add_new_option").append(add_option_view);
            });
        });

        function show_min_max(data) {
            $('#min_max1_' + data).removeAttr("readonly");
            $('#min_max2_' + data).removeAttr("readonly");
            $('#min_max1_' + data).attr("required", "true");
            $('#min_max2_' + data).attr("required", "true");
        }

        function hide_min_max(data) {
            $('#min_max1_' + data).val(null).trigger('change');
            $('#min_max2_' + data).val(null).trigger('change');
            $('#min_max1_' + data).attr("readonly", "true");
            $('#min_max2_' + data).attr("readonly", "true");
            $('#min_max1_' + data).attr("required", "false");
            $('#min_max2_' + data).attr("required", "false");
        }

        function new_option_name(value, data) {
            $("#new_option_name_" + data).empty();
            $("#new_option_name_" + data).text(value)
            console.log(value);
        }

        function removeOption(e) {
            element = $(e);
            element.parents('.view_new_option').remove();
        }

        function deleteRow(e) {
            element = $(e);
            element.parents('.add_new_view_row_class').remove();
        }


        function add_new_row_button(data) {
            count = data;
            countRow = 1 + $('#option_price_view_' + data).children('.add_new_view_row_class').length;
            var add_new_row_view = `
                <div class="row add_new_view_row_class mb-3 position-relative pt-3 pt-sm-0">
                    <div class="col-md-4 col-sm-5">
                        <label for="">{{ translate('Option_name') }}</label>
                        <input class="form-control" required type="text" name="options[` + count + `][values][` + countRow + `][label]" id="">
                    </div>
                    <div class="col-md-4 col-sm-5">
                        <label for="">{{ translate('Additional_price') }}</label>
                        <input class="form-control"  required type="number" min="0" step="0.01" name="options[` + count + `][values][` + countRow + `][optionPrice]" id="">
                    </div>
                    <div class="col-sm-2 max-sm-absolute">
                        <label class="d-none d-sm-block">&nbsp;</label>
                        <div class="mt-1">
                            <button type="button" class="btn btn-danger btn-sm" onclick="deleteRow(this)"title="{{ translate('Delete') }}">
                                    <i class="tio-add-to-trash"></i>
                            </button>
                        </div>
                    </div>
                </div>`;
            $('#option_price_view_' + data).append(add_new_row_view);
        }
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
            if(lang == '{{$defaultLang}}')
            {
                $("#from_part_2").removeClass('d-none');
            }
            else
            {
                $("#from_part_2").addClass('d-none');
            }


        })
    </script>

    <script>
        //Select 2
        $("#choose_addons").select2({
            placeholder: "Select Addons",
            allowClear: true
        });

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
                url: '{{route('admin.product.store')}}',
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
                        toastr.success('{{translate("product added successfully!")}}', {
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
        function update_qty() {
            var total_qty = 0;
            var qty_elements = $('input[name^="stock_"]');
            for(var i=0; i<qty_elements.length; i++)
            {
                total_qty += parseInt(qty_elements.eq(i).val());
            }
            if(qty_elements.length > 0)
            {
                $('input[name="total_stock"]').attr("readonly", true);
                $('input[name="total_stock"]').val(total_qty);
                console.log(total_qty)
            }
            else{
                $('input[name="total_stock"]').attr("readonly", false);
            }
        }
    </script>

    <script>
        $("#discount_type").change(function(){
            if(this.value === 'amount') {
                $("#discount_label").text("{{translate('discount_amount')}}");
                $("#discount_input").attr("placeholder", "{{translate('Ex: 500')}}")
            }
            else if(this.value === 'percent') {
                $("#discount_label").text("{{translate('discount_percent')}}")
                $("#discount_input").attr("placeholder", "{{translate('Ex: 50%')}}")
            }
        });

        $("#tax_type").change(function(){
            if(this.value === 'amount') {
                $("#tax_label").text("{{translate('tax_amount')}}");
                $("#tax_input").attr("placeholder", "{{translate('Ex: 500')}}")
            }
            else if(this.value === 'percent') {
                $("#tax_label").text("{{translate('tax_percent')}}")
                $("#tax_input").attr("placeholder", "{{translate('Ex: 50%')}}")
            }
        });


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




