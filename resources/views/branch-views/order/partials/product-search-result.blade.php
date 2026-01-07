<div class="p-3 card card-body d-flex flex-column gap-2 overflow-y-auto max-h-300px">
    @forelse($searchProducts as $product)
        <a href="javascript:" class="product-search-dropdown-item border rounded-10 bg-white add-to-cart-from-search
        {{ $product->available_stock_computed !== null && $product->available_stock_computed <= 0 ? 'disabled' : ''  }}"
           data-order-id="{{ $orderId }}"
           data-branch-id="{{ $branchId }}"
           data-name="{{ $product->name }}"
           data-price="{{ $product->price_computed }}"
           data-discount="{{ $product->discount_computed }}"
           data-final-price="{{ $product->final_price_computed }}"
           data-stock-type="{{ $product->stock_type_computed }}"
           data-stock="{{ $product->available_stock_computed }}"
           data-variation-count="{{ $product->variation_count }}"
           data-variation="{{ $product->variation }}"
           data-image="{{ $product->image }}"
           data-product-id="{{ $product->id }}">
            <div class="d-flex justify-content-between align-items-center gap-2 flex-wrap p-2 text-body">
                <div class="flex-grow-1 d-flex gap-2 align-items-center">
                    <img width="65" class="avatar-img ratio-1"
                         src="{{ $product->imageFullPath }}" alt="{{ $product->name }}">
                    <div class="flex-grow-1">
                        <div class="fz-13 text-title line-limit-1 max-w180 product_title">
                            {{ Str::limit($product->name, 50) }}
                        </div>
                        <div class="fz-12 d-flex gap-1">
                            <span>{{ translate('Stock Qty') }}</span> :
                            <span class="text-title product_stock_qty">{{ ucfirst($product->stock_type_computed) }}</span>
                            @if($product->available_stock_computed !== null)
                                <span>{{ $product->available_stock_computed }}</span>
                            @endif
                        </div>
                        @if($product->is_added)
                            <span class="btn btn-primary py-1 lh-1 px-2 fz-10 rounded">
                                {{ translate('Already Added') }}
                            </span>
                        @endif
                    </div>
                </div>

                <div>
                    <div class="fz-13 text-title text-sm-right">{{ translate('Price') }}</div>
                    <div class="fz-12 d-flex gap-1">
                        @if($product->discount_computed > 0)
                            <span class="text-line-through">{{ Helpers::set_symbol($product->price_computed) }}</span>
                        @endif
                        <span class="text-title font-weight-semibold">
                            {{ Helpers::set_symbol($product->final_price_computed) }}
                        </span>
                    </div>
                </div>
            </div>
        </a>
    @empty
        <div class="text-center gap-2 py-5 px-3 bg-light border rounded">
            <p class="text-center text-muted m-0">{{ translate('No products found') }}</p>
        </div>
    @endforelse
</div>
