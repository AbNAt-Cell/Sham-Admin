<div class="modal z--9999 fade modal-custom-overlay" id="variationProductModal" tabindex="-1" aria-modal="true" role="dialog">
    <div class="modal-dialog modal-dialog-centered modal-dialog-scrollable">
        <div class="modal-content" id="quick-view">
            <div class="modal-header p-2">
                <h4 class="modal-title product-title"></h4>
                <button type="button" class="btn btn-soft-secondary square-btn rounded-circle" data-dismiss="modal" aria-label="Close">
                    <i class="tio-clear"></i>
                </button>
            </div>
            <form id="add-to-cart-form">
                <div class="modal-body pt-0">
                    <div class="d-flex flex-wrap gap-3">
                        <div class="d-flex align-items-center justify-content-center active">
                            <img class="img-responsive rounded ratio-1 object-cover" width="170"
                                 src="{{ $product?->imageFullPath }}"
                                 alt="Product">
                        </div>

                        <div class="details">
                            <div class="break-all">
                                <a href="#" class="d-block h3 mb-2 product-title product-title">
                                    {{ Str::limit($product?->name, 100) }}
                                </a>
                            </div>

                            <div class="mb-2 text-dark d-flex align-items-center gap-2">
                                @if($productData['discount'] > 0)
                                    <strike class="fz-12">
                                        {{Helpers::set_symbol($productData['price'] ?? 0) }}
                                    </strike>
                                @endif

                                <h4 class="text-accent mb-0">
                                    {{Helpers::set_symbol($productData['final_price'] ?? 0) }}
                                </h4>
                                <span class="badge badge-danger p-1 fz-13">
                                    -{{Helpers::set_symbol($productData['discount'] ?? 0) }}
                                </span>
                            </div>
                            <div class="mb-3 text-title d-flex align-items-center gap-3 border px-3 py-2 rounded fz-12">
                                <span>{{ translate('ID') }} #{{ $product?->id }}</span>
                                @if($productData['stock_type'] ?? '' == 'unlimited')
                                    <span class="dot-before"><i class="tio-cube mr-1"></i>{{ translate('unlimited') }}</span>
                                @else
                                    <span class="dot-before"><i class="tio-cube mr-1"></i>{{ translate('only') }} {{ $productData['available_stock'] }} {{ translate('left') }}</span>
                                @endif
                            </div>
                            <div>
                                <span class="badge badge-soft-secondary fz-12 px-3 py-2 text-title">
                                    <img width="13" class="mr-1" src="{{asset('public/assets/admin/img/icons/leaf.svg')}}" alt="{{ translate('veg tag') }}">
                                    {{ translate($product?->product_type) }}
                                </span>
                                @php($halalTagStatus = (integer) (\App\CentralLogics\Helpers::get_business_settings('halal_tag_status') ?? 0))
                                @if($halalTagStatus && $productData['halal_status'] ?? 0 )
                                    <span class="badge badge-soft-secondary fz-12 px-3 py-2 text-title">
                                        <img width="13" class="mr-1" src="{{asset('public/assets/admin/img/halal-tags.png')}}" alt="{{ translate('halal tag') }}">{{ translate("Halal") }}
                                    </span>
                                @endif
                            </div>
                        </div>
                    </div>
                    <div class="row pt-2">
                        <div class="col-12">

                            @if($product?->description)
                                <h3 class="mt-3">{{translate('description')}}</h3>
                                <div class="d-block text-break text-dark __descripiton-txt __not-first-hidden min-h-auto">
                                    <div>
                                        <p>
                                            {!! $product?->description !!}
                                        </p>
                                    </div>
                                    <div class="show-more text-info text-center">
                                        <span class="">See More</span>
                                    </div>
                                </div>
                            @endif

                            <div class="d-flex flex-column gap-3">
                                <input type="hidden" name="id" value="{{ $product->id }}">
                                <input type="hidden" name="order_id" value="{{ $orderId }}">
                                <input type="hidden" name="branch_id" value="{{ $branchId }}">

                                <div class="d-flex flex-column gap-4">
                                    @foreach ($productData['variations'] as $key => $choice)
                                        @if (isset($choice->price) == false)
                                            <div class="border rounded p-3 variation-group">
                                                <div class="h3 p-0 d-flex justify-content-between align-items-center">
                                                    <span>{{ $choice['name'] }}</span>
                                                    <span class="badge badge-soft-secondary font-weight-medium variant-name-optional-or-required-label">{{ ($choice['required'] == 'on')  ?  translate('Required') : translate('optional') }}</span>
                                                </div>
                                                @if ($choice['min'] != 0 && $choice['max'] != 0)
                                                    <small class="d-block mb-3">
                                                        {{ translate('You_need_to_select_minimum_ ') }} {{ $choice['min'] }} {{ translate('to_maximum_ ') }} {{ $choice['max'] }} {{ translate('options') }}
                                                    </small>
                                                @endif

                                                <div class="d-flex flex-column gap-2 mt-3">
                                                    <input type="hidden"  name="variations[{{ $key }}][min]" value="{{ $choice['min'] }}" >
                                                    <input type="hidden"  name="variations[{{ $key }}][max]" value="{{ $choice['max'] }}" >
                                                    <input type="hidden"  name="variations[{{ $key }}][required]" value="{{ $choice['required'] }}" >
                                                    <input type="hidden" name="variations[{{ $key }}][name]" value="{{ $choice['name'] }}">
                                                    @foreach ($choice['values'] as $k => $option)
                                                        <div class="d-flex form--check form-check user-select-none">
                                                            <div class="d-flex gap-2">
                                                                <input class="form-check-input variation-input" type="{{ ($choice['type'] == "multi") ? "checkbox" : "radio"}}" id="choice-option-{{ $key }}-{{ $k }}"
                                                                       name="variations[{{ $key }}][values][label][]" value="{{ $option['label'] }}" autocomplete="off">

                                                                <label class="form-check-label"
                                                                       for="choice-option-{{ $key }}-{{ $k }}">{{ Str::limit($option['label'], 20, '...') }}</label>
                                                            </div>
                                                            <span class="ml-auto">{{ Helpers::set_symbol($option['optionPrice']) }}</span>
                                                        </div>
                                                    @endforeach
                                                </div>
                                            </div>
                                        @endif
                                    @endforeach
                                </div>

                                @php($add_ons = json_decode($product->add_ons))
                                @if(count($add_ons)>0)
                                    <div class="p-3 shadow rounded-10">
                                        <h3>{{ translate('addon') }}</h3>
                                        <div class="d-flex flex-column gap-2 addon-wrap">
                                            @foreach (\App\Model\AddOn::whereIn('id', $add_ons)->get() as $key => $add_on)
                                                <div class="addon-item d-flex gap-3 justify-content-between align-items-center">
                                                    <input type="hidden" name="addon-price{{ $add_on->id }}" value="{{$add_on->price}}">
                                                    <div class="d-flex align-items-center gap-2">
                                                        <input class="addon-chek" type="checkbox"
                                                               id="addon{{ $key }}" onchange="addon_quantity_input_toggle(event)"
                                                               name="addon_id[]" value="{{ $add_on->id }}"
                                                               autocomplete="off">
                                                        <label class="user-select-none mb-0 text-black-50 fw-medium addon_label"
                                                               for="addon{{ $key }}">{{ $add_on->name }}
                                                        </label>
                                                    </div>
                                                    <div class="d-flex align-items-baseline gap-3 flex-wrap">
                                                        <span class="user-select-none mb-0 text-black-50 fw-medium fz-12 addon_label"
                                                              for="addon{{ $key }}">
                                                            {{ \App\CentralLogics\Helpers::set_symbol($add_on->price) }}
                                                        </span>
                                                        <label class="input-group addon-quantity-input addon-quantity-input_custom shadow bg-white rounded mb-0 d-none align-items-center w-auto fz-12"
                                                               for="addon{{ $key }}">
                                                            <button class="btn btn-sm h-100 text-dark pl-1 py-1 pr-0" type="button">
                                                                <i class="tio-remove  font-weight-bold"></i></button>
                                                            <input type="number" name="addon-quantity{{ $add_on->id }}"
                                                                   class="text-center border-0 h-100"
                                                                   placeholder="1" value="1" min="1" max="100" readonly>
                                                            <button class="btn btn-sm h-100 text-dark pr-1 py-1 pl-0" type="button">
                                                                <i class="tio-add  font-weight-bold"></i></button>
                                                        </label>
                                                    </div>
                                                </div>
                                            @endforeach
                                        </div>
                                    </div>
                                @endif
                            </div>
                        </div>
                    </div>
                </div>
                <div class="modal-footer shadow-lg bg-white border-0 d-block">
                    <div class="d-flex align-items-center justify-content-between" id="chosen_price_div">
                        <div class="product-description-label font-weight-bold text-dark fz-16">{{translate('Total_Price')}}</div>
                        <input type="hidden" id="base_price" value="{{ $productData['final_price'] ?? 0 }}">
                        <div class="product-price font-weight-bold text-dark fz-20"><strong id="chosen_price">{{ Helpers::set_symbol($productData['final_price']) }}</strong></div>
                    </div>

                    <div class="d-flex align-items-center justify-content-between mt-3">
                        <div class="product-quantity d-flex align-items-center">
                            <div class="product-quantity-group d-flex align-items-center border-0">
                                <button class="btn btn-number text-dark p-2 variation-quantity-update-btn" type="button"
                                        data-type="minus"
                                        data-field="quantity"
                                        data-stock_type="{{ $productData['stock_type'] }}">
                                    <i class="tio-remove font-weight-bold"></i>
                                </button>

                                <input type="text" name="quantity"
                                       class="form-control input-number text-center variation-cart-qty-field" placeholder="1"
                                       value="1" min="1"
                                       max="999" readonly>

                                <button class="btn btn-number text-dark p-2 variation-quantity-update-btn" type="button"
                                        data-type="plus"
                                        data-field="quantity"
                                        data-stock_type="{{ $productData['stock_type'] }}">
                                    <i class="tio-add font-weight-bold"></i>
                                </button>
                            </div>
                        </div>
                        <button class="btn btn-primary px-md-5 product-variation-add-to-cart-button" type="button">
                            <i class="tio-shopping-cart"></i>
                            {{ translate(' Add To Cart') }}
                        </button>
                    </div>
                </div>
            </form>
        </div>
    </div>

</div>
