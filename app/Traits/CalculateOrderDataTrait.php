<?php

namespace App\Traits;

use App\CentralLogics\Helpers;
use App\Model\AddOn;
use App\Model\Coupon;
use App\Model\Order;
use App\Model\Product;
use App\Model\ProductByBranch;
use App\Model\WalletTransaction;
use App\Models\OrderPartialPayment;
use App\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Str;
use function App\CentralLogics\translate;

trait CalculateOrderDataTrait
{
    protected function calculateOrderAmount(array $cart, int|string $userId, int $isGuest, array $deliveryChargeInfo = [],  ?string $couponCode = null): array|JsonResponse
    {
        if (empty($cart)) {
            return [
                'order_amount' => 0,
                'coupon_discount_amount' => 0,
                'delivery_charge_amount' => 0,
                'total_product_tax_amount' => 0,
                'total_product_price' => 0,
                'total_discount_on_product' => 0,
                'total_addon_price' => 0,
                'referral_discount_amount' => 0,
                'coupon_code' => null
            ];
        }

        $totalOrderedAmount = 0;
        $couponDiscountAmount = 0;
        $deliveryChargeAmount = 0;
        $totalProductTaxAmount = 0;
        $totalProductPrice = 0;
        $totalDiscountOnProduct = 0;
        $totalAddonPrice = 0;
        $totalAddonTax = 0;
        $referralDiscountAmount = 0;
        $appliedCouponCode = null;

        foreach ($cart as $cartItem) {
            $product = Product::find($cartItem['product_id']);
            $branchProduct = ProductByBranch::
                where([
                    'product_id' => $cartItem['product_id'],
                    'branch_id' => $deliveryChargeInfo['branch_id']
                    ])
                ->first();

            //daily and fixed stock quantity validation
            if ($branchProduct && ($branchProduct->stock_type == 'daily' || $branchProduct->stock_type == 'fixed')) {
                $availableStock = $branchProduct->stock - $branchProduct->sold_quantity;
                if ($availableStock < $cartItem['quantity']) {
                    return response()->json([
                        'errors' => [[
                            'code' => 'stock',
                            'message' => translate('stock limit exceeded')
                        ]]
                    ], 403);
                }
            }

            $discountData = [];
            $product->halal_status = $branchProduct?->halal_status ?? 0;

            if ($branchProduct) {
                $branchProductVariations = $branchProduct->variations;
                $variations = [];

                if (count($branchProductVariations)) {
                    $variationData = Helpers::get_varient($branchProductVariations, $cartItem['variations']);
                    $price = $branchProduct['price'] + $variationData['price'];
                    $variations = $variationData['variations'];
                } else {
                    $price = $branchProduct['price'];
                }
                $discountData = [
                    'discount_type' => $branchProduct['discount_type'],
                    'discount' => $branchProduct['discount'],
                ];
            } else {
                $productVariations = json_decode($product->variations, true);
                $variations = [];

                if (count($productVariations)) {
                    $variationData = Helpers::get_varient($productVariations, $cartItem['variations']);
                    $price = $product['price'] + $variationData['price'];
                    $variations = $variationData['variations'];
                } else {
                    $price = $product['price'];
                }
                $discountData = [
                    'discount_type' => $product['discount_type'],
                    'discount' => $product['discount'],
                ];
            }

            $discountOnProduct = Helpers::discount_calculate($discountData, $price);

            /*calculation for addon and addon tax start*/
            $addonQuantities = $cartItem['add_on_qtys'];
            $addonPrices = [];
            $addonTaxes = [];

            foreach($cartItem['add_on_ids'] as $key =>$id){
                $addon = AddOn::find($id);
                if ($addon) {
                    $addonPrices[] = $addon['price'];
                    $addonTaxes[] = ($addon['price'] * $addon['tax']) / 100;
                }
            }

            $addonTaxForThisItem = array_reduce(
                array_map(function ($a, $b) {
                    return $a * $b;
                }, $addonQuantities, $addonTaxes),
                function ($carry, $item) {
                    return $carry + $item;
                },
                0
            );
            /*calculation for addon and addon tax end*/

            $addonPrice = array_reduce(
                array_map(function ($a, $b) {
                    return $a * $b;
                }, $addonQuantities, $addonPrices),
                function ($carry, $item) {
                    return $carry + $item;
                },
                0
            );

            $productTaxAmount =  Helpers::new_tax_calculate($product, $price, $discountData);

            $totalProductTaxAmount += $productTaxAmount * $cartItem['quantity'];
            $totalProductPrice += $price * $cartItem['quantity'];
            $totalDiscountOnProduct += $discountOnProduct * $cartItem['quantity'];;
            $totalAddonPrice += $addonPrice;
            $totalAddonTax += $addonTaxForThisItem;

        }

        $totalPriceForCalculation = (($totalProductPrice  - $totalDiscountOnProduct) + $totalAddonPrice);

        if ($isGuest == 0 && $userId != null) {
            $registeredCustomer = User::find($userId);
            if ($registeredCustomer &&
                $registeredCustomer?->referral_customer_details &&
                $registeredCustomer?->referral_customer_details?->customer_discount_amount > 0 &&
                $registeredCustomer?->referral_customer_details?->is_used == 0
            ) {
                $referralDiscountAmount = $this->calculateReferralDiscount(
                    referral: $registeredCustomer?->referral_customer_details,
                    orderAmount: $totalPriceForCalculation
                );
            }
        }

        $totalPriceForCalculation -= $referralDiscountAmount;

        if (!empty($couponCode)) {
            $couponData = $this->applyCoupon(
                code: $couponCode,
                amount: $totalPriceForCalculation,
                userId: $userId,
                isGuest: $isGuest
            );
            $couponDiscountAmount = $couponData['coupon_discount_amount'];
            $appliedCouponCode = $couponData['code'];
        }

        $totalOrderedAmount = $totalProductPrice
            + $totalProductTaxAmount
            + $totalAddonPrice
            + $totalAddonTax
            - $totalDiscountOnProduct
            - $couponDiscountAmount
            - $referralDiscountAmount;

        if (isset($deliveryChargeInfo['order_type']) && $deliveryChargeInfo['order_type'] !== 'take_away') {
            $deliveryChargeAmount = Helpers::get_delivery_charge(
                branchId: $deliveryChargeInfo['branch_id'],
                distance: $deliveryChargeInfo['distance'],
                selectedDeliveryArea: $deliveryChargeInfo['selected_delivery_area'],
                orderAmount: $totalOrderedAmount
            );
        }

        return [
            'order_amount' => $totalOrderedAmount,
            'coupon_discount_amount' => $couponDiscountAmount,
            'delivery_charge_amount' => $deliveryChargeAmount,
            'total_product_tax_amount' => $totalProductTaxAmount,
            'total_product_and_addon_tax_amount' => $totalProductTaxAmount + $totalAddonTax,
            'total_product_price' => $totalProductPrice,
            'total_discount_on_product' => $totalDiscountOnProduct,
            'total_addon_price' => $totalAddonPrice,
            'referral_discount_amount' => $referralDiscountAmount,
            'coupon_code' => $appliedCouponCode
        ];
    }

    protected function calculateEditOrderAmount(array $cart, $order): array|JsonResponse
    {
        if (empty($cart)) {
            return [
                'order_amount' => 0,
                'coupon_discount_amount' => 0,
                'delivery_charge_amount' => 0,
                'total_product_tax_amount' => 0,
                'total_product_price' => 0,
                'total_discount_on_product' => 0,
                'total_addon_price' => 0,
                'referral_discount_amount' => 0,
                'coupon_code' => null
            ];
        }

        $totalOrderedAmount = 0;
        $couponDiscountAmount = 0;
        $deliveryChargeAmount = 0;
        $totalProductTaxAmount = 0;
        $totalProductPrice = 0;
        $totalDiscountOnProduct = 0;
        $totalAddonPrice = 0;
        $totalAddonTax = 0;
        $referralDiscountAmount = 0;
        $appliedCouponCode = null;

        foreach ($cart as $cartItem) {
            $product = Product::find($cartItem['id']);
            $branchProduct = ProductByBranch::
                where([
                    'product_id' => $cartItem['id'],
                    'branch_id' => $order['branch_id']
                ])
                ->first();

            //daily and fixed stock quantity validation
            if ($branchProduct && ($branchProduct->stock_type == 'daily' || $branchProduct->stock_type == 'fixed')) {
                $availableStock = $branchProduct->stock - $branchProduct->sold_quantity;
                if ($availableStock < $cartItem['quantity']) {
                    return response()->json([
                        'errors' => [[
                            'code' => 'stock',
                            'message' => translate('stock limit exceeded')
                        ]]
                    ], 403);
                }
            }


            if ($branchProduct) {
                $branchProductVariations = $branchProduct->variations;
                $variations = [];

                if (count($branchProductVariations)) {
                    $new = json_decode($cartItem['variation'], true);

                    foreach ($new as &$item) {
                        if (isset($item['values']) && is_array($item['values'])) {
                            $item['values'] = [
                                'label' => array_column($item['values'], 'label')
                            ];
                        }
                    }
                    unset($item);

                    $variationData = Helpers::get_varient($branchProductVariations, $new);

                    $price = $branchProduct['price'] + $variationData['price'];
                    $variations = $variationData['variations'];
                } else {
                    $price = $branchProduct['price'];
                }
                $discountData = [
                    'discount_type' => $branchProduct['discount_type'],
                    'discount' => $branchProduct['discount'],
                ];
            } else {
                $productVariations = json_decode($product->variations, true);
                $variations = [];

                if (count($productVariations)) {
                    $new = json_decode($cartItem['variation'], true);

                    foreach ($new as &$item) {
                        if (isset($item['values']) && is_array($item['values'])) {
                            $item['values'] = [
                                'label' => array_column($item['values'], 'label')
                            ];
                        }
                    }
                    unset($item);

                    $variationData = Helpers::get_varient($productVariations, $new);

                    $price = $product['price'] + $variationData['price'];
                    $variations = $variationData['variations'];
                } else {
                    $price = $product['price'];
                }
                $discountData = [
                    'discount_type' => $product['discount_type'],
                    'discount' => $product['discount'],
                ];
            }

            $discountOnProduct = Helpers::discount_calculate($discountData, $price);

            /*calculation for addon and addon tax start*/
            $addonQuantities = $cartItem['add_on_qtys'];
            $addonIds = $cartItem['add_on_ids'] ?? [];
            $addonPrices = [];
            $addonTaxes = [];

            foreach($addonIds as $key =>$id){
                $addon = AddOn::find($id);
                if ($addon) {
                    $addonPrices[] = $addon['price'];
                    $addonTaxes[] = ($addon['price'] * $addon['tax']) / 100;
                }
            }

            $addonTaxForThisItem = array_reduce(
                array_map(function ($a, $b) {
                    return $a * $b;
                }, $addonQuantities, $addonTaxes),
                function ($carry, $item) {
                    return $carry + $item;
                },
                0
            );
            /*calculation for addon and addon tax end*/

            $addonPrice = array_reduce(
                array_map(function ($a, $b) {
                    return $a * $b;
                }, $addonQuantities, $addonPrices),
                function ($carry, $item) {
                    return $carry + $item;
                },
                0
            );

            $productTaxAmount =  Helpers::new_tax_calculate($product, $price, $discountData);

            $totalProductTaxAmount += $productTaxAmount * $cartItem['quantity'];
            $totalProductPrice += $price * $cartItem['quantity'];
            $totalDiscountOnProduct += $discountOnProduct * $cartItem['quantity'];;
            $totalAddonPrice += $addonPrice;
            $totalAddonTax += $addonTaxForThisItem;

        }

        $totalPriceForCalculation = $totalProductPrice  - $totalDiscountOnProduct + $totalAddonPrice;

        if ($order['referral_discount'] > 0 && $order['is_guest'] == 0){
            $registeredCustomer = User::find($order['user_id']);
            $referralData = $registeredCustomer?->referral_customer_details;

            if ($registeredCustomer && $referralData) {
                $discountAmount = (float)($referralData->customer_discount_amount ?? 0);
                $discountType   = $referralData->customer_discount_amount_type ?? 'amount';

                $calculatedDiscount= $discountType == 'percent'
                    ? ($totalPriceForCalculation * $discountAmount) / 100
                    : $discountAmount;

                $referralDiscountAmount = min($calculatedDiscount, $totalPriceForCalculation);

            }
        }


        $totalPriceForCalculation -=  $referralDiscountAmount;

        if (!empty($order['coupon_code'])) {
            $couponData = $this->editOrderApplyCoupon(
                code: $order['coupon_code'],
                amount: $totalPriceForCalculation,
            );
            $couponDiscountAmount = $couponData['coupon_discount_amount'];
            $appliedCouponCode = $couponData['code'];
        }

        $totalOrderedAmount = $totalProductPrice
            + $totalProductTaxAmount
            + $totalAddonPrice
            + $totalAddonTax
            - $totalDiscountOnProduct
            - $couponDiscountAmount
            - $referralDiscountAmount;

//        if ($order['order_type'] !== 'take_away') {
//            $deliveryChargeAmount = Helpers::get_delivery_charge(
//                branchId: $order['branch_id'],
//                distance: $order['distance'],
//                selectedDeliveryArea: $order->order_area->area_id,
//                orderAmount: $totalOrderedAmount
//            );
//        }

        $deliveryChargeAmount = $order['delivery_charge'];

        return [
            'order_amount' => $totalOrderedAmount,
            'coupon_discount_amount' => $couponDiscountAmount,
            'delivery_charge_amount' => $deliveryChargeAmount,
            'total_product_tax_amount' => $totalProductTaxAmount,
            'total_product_and_addon_tax_amount' => $totalProductTaxAmount + $totalAddonTax,
            'total_product_price' => $totalProductPrice,
            'total_discount_on_product' => $totalDiscountOnProduct,
            'total_addon_price' => $totalAddonPrice,
            'referral_discount_amount' => $referralDiscountAmount,
            'coupon_code' => $appliedCouponCode
        ];
    }

    protected function applyCoupon(string $code, float $amount, int|string $userId, int $isGuest): array
    {
        $coupon = Coupon::active()->where(['code' => $code])->first();

        if (!$coupon) {
            return [
                'coupon_discount_amount' => 0,
                'code' => null
            ];
        }

        if ($coupon['min_purchase'] && $amount < $coupon['min_purchase']) {
            return [
                'coupon_discount_amount' => 0,
                'code' => null,
            ];
        }

        // Check First Order Coupon
        if ($coupon['coupon_type'] == 'first_order') {
            if ($isGuest == 1) {
                return [
                    'coupon_discount_amount' => 0,
                    'code' => null
                ];
            }

            $totalOrders = Order::where(['user_id' => $userId, 'is_guest' => 0])->count();
            if ($totalOrders > 0) {
                return [
                    'coupon_discount_amount' => 0,
                    'code' => null
                ];
            }
        }

        // Check usage limit
        if ($coupon['limit'] !== null) {
            $usageCount = Order::where(['user_id' => $userId, 'coupon_code' => $code, 'is_guest' => $isGuest])
                ->count();

            if ($usageCount >= $coupon['limit']) {
                return [
                    'coupon_discount_amount' => 0,
                    'code' => null
                ];
            }
        }

        // 🔹 Calculate discount
        $discount = 0;

        if ($coupon['discount_type'] === 'percent') {
            $discount = ($amount * $coupon['discount']) / 100;

            if ($coupon['max_discount'] > 0 && $discount > $coupon['max_discount']) {
                $discount = $coupon['max_discount'];
            }
        } else { // fixed amount
            $discount = $coupon['discount'];
        }

        if ($discount > $amount) {
            $discount = $amount;
        }

        return [
            'coupon_discount_amount' => $discount,
            'code' => $coupon['code'],
        ];

    }

    protected function editOrderApplyCoupon(string $code, float $amount): array
    {
        $coupon = Coupon::where(['code' => $code])->first();

        if (!$coupon) {
            return [
                'coupon_discount_amount' => 0,
                'code' => null
            ];
        }

        if ($coupon['min_purchase'] && $amount < $coupon['min_purchase']) {
            return [
                'coupon_discount_amount' => 0,
                'code' => null,
            ];
        }


        $discount = 0;

        if ($coupon['discount_type'] === 'percent') {
            $discount = ($amount * $coupon['discount']) / 100;

            if ($coupon['max_discount'] > 0 && $discount > $coupon['max_discount']) {
                $discount = $coupon['max_discount'];
            }
        } else {
            $discount = $coupon['discount'];
        }

        if ($discount > $amount) {
            $discount = $amount;
        }

        return [
            'coupon_discount_amount' => $discount,
            'code' => $coupon['code'],
        ];

    }


    protected function editOrderWalletAdjustment($order, $newOrderAmountWithDeliveryCharge, $oldOrderAmountWithDeliveryCharge)
    {
        $customer = User::find($order['user_id']);
        if (!$customer) return;

        $walletBalance = $customer->wallet_balance;
        $difference = $newOrderAmountWithDeliveryCharge - $oldOrderAmountWithDeliveryCharge;

        // Case 1: Partial payments already exist
        if ($order->order_partial_payments()->exists()) {
            $walletPartial = $order->order_partial_payments()->where('paid_with', 'wallet_payment')->first();
            $codPartial = $order->order_partial_payments()->where('paid_with', 'cash_on_delivery')->first();

            // New total is greater → increase due amounts
            if ($difference > 0) {
                if ($codPartial) {
                    $codPartial->due_amount = 0;
                    $codPartial->paid_amount = $difference;
                    $codPartial->save();
                }

                if ($walletPartial) {
                    $walletPartial->due_amount = $difference;
                    $walletPartial->save();
                }
            }
            // New total is smaller → adjust due/refund
            elseif ($difference < 0) {
                $refundAmount = abs($difference);

                if ($codPartial) {
                    $codPartial->paid_amount = max(0, $codPartial->paid_amount - $refundAmount);
                    $codPartial->save();
                }

                if ($walletPartial) {
                    $walletPartial->due_amount = max(0, $walletPartial->due_amount - $refundAmount);

                    // Refund the wallet part to the customer balance
                    $customer->wallet_balance += min($walletPartial->paid_amount, $refundAmount);
                    $customer->save();

                    // Create wallet transaction for refund
                    WalletTransaction::create([
                        'user_id' => $customer->id,
                        'transaction_id' => Str::random(30),
                        'reference' => $order['id'],
                        'transaction_type' => 'order_refund',
                        'credit' => min($walletPartial->paid_amount, $refundAmount),
                        'debit' => 0,
                        'balance' => $customer->wallet_balance,
                    ]);

                    $walletPartial->save();
                }
            }

        }
        // Case 2: Normal wallet payment (no partials yet)
        else {
            // Refund
            if ($difference < 0) {
                $refundAmount = abs($difference);
                $customer->wallet_balance += $refundAmount;
                $customer->save();

                WalletTransaction::create([
                    'user_id' => $customer->id,
                    'transaction_id' => Str::random(30),
                    'reference' => $order['id'],
                    'transaction_type' => 'order_refund',
                    'credit' => $refundAmount,
                    'debit' => 0,
                    'balance' => $customer->wallet_balance,
                ]);
            }
            // Extra payment
            elseif ($difference > 0) {
                if ($walletBalance >= $difference) {
                    $customer->wallet_balance -= $difference;
                    $customer->save();

                    WalletTransaction::create([
                        'user_id' => $customer->id,
                        'transaction_id' => Str::random(30),
                        'reference' => $order['id'],
                        'transaction_type' => 'order_place',
                        'credit' => 0,
                        'debit' => $difference,
                        'balance' => $customer->wallet_balance,
                    ]);
                } else {
                    $remainingDue = $difference - $walletBalance;

                    if ($walletBalance > 0) {
                        WalletTransaction::create([
                            'user_id' => $customer->id,
                            'transaction_id' => Str::random(30),
                            'reference' => $order['id'],
                            'transaction_type' => 'order_place',
                            'credit' => 0,
                            'debit' => $walletBalance,
                            'balance' => 0,
                        ]);
                        $customer->wallet_balance = 0;
                        $customer->save();
                    }

                    OrderPartialPayment::create([
                        'order_id' => $order['id'],
                        'paid_with' => 'wallet_payment',
                        'paid_amount' => $walletBalance,
                        'due_amount' => $remainingDue,
                    ]);

                    OrderPartialPayment::create([
                        'order_id' => $order['id'],
                        'paid_with' => 'cash_on_delivery',
                        'paid_amount' => $remainingDue,
                        'due_amount' => 0,
                    ]);
                }
            }
        }
    }

    protected function  calculateReferralDiscount($referral, $orderAmount): float
    {
        // Check discount validity
        $validityValue = (int)($referral->customer_discount_validity ?? 0);
        $validityType = $referral->customer_discount_validity_type ?? 'day';
        $isValid = true;

        if ($validityValue > 0) {
            $createdAt = $referral->created_at;

            $validUntil = match ($validityType) {
                'day'   => $createdAt->copy()->addDays($validityValue),
                'week'  => $createdAt->copy()->addWeeks($validityValue),
                'month' => $createdAt->copy()->addMonths($validityValue),
                default => $createdAt,
            };

            $isValid = now()->lte($validUntil); // Check if still valid
        }

        if (!$isValid) {
            return 0;
        }

        // Calculate discount
        $discountAmount = (float)($referral->customer_discount_amount ?? 0);
        $discountType   = $referral->customer_discount_amount_type ?? 'amount';

        $calculatedDiscount = $discountType == 'percent'
            ? ($orderAmount * $discountAmount) / 100
            : $discountAmount;

        // Make sure discount does not exceed order amount
        $finalDiscount = min($calculatedDiscount, $orderAmount);

        return $finalDiscount;
    }

}
