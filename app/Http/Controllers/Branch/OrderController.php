<?php

namespace App\Http\Controllers\Branch;

use App\CentralLogics\CustomerLogic;
use App\CentralLogics\Helpers;
use App\CentralLogics\OrderLogic;
use App\Http\Controllers\Controller;
use App\Model\AddOn;
use App\Model\Branch;
use App\Model\BusinessSetting;
use App\Model\CustomerAddress;
use App\Model\DeliveryHistory;
use App\Model\Order;
use App\Model\OrderDetail;
use App\Model\Product;
use App\Model\ProductByBranch;
use App\Models\DeliveryChargeByArea;
use App\Models\GuestUser;
use App\Models\OfflinePayment;
use App\Models\OrderArea;
use App\Models\OrderPartialPayment;
use App\Models\ReferralCustomer;
use App\Traits\CalculateOrderDataTrait;
use App\User;
use Brian2694\Toastr\Facades\Toastr;
use Carbon\Carbon;
use DateTime;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\View\Factory;
use Illuminate\Contracts\View\View;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Mail;
use Illuminate\Validation\ValidationException;
use Rap2hpoutre\FastExcel\FastExcel;
use Illuminate\Http\RedirectResponse;
use Illuminate\Contracts\Support\Renderable;
use Symfony\Component\HttpFoundation\StreamedResponse;
use function App\CentralLogics\translate;

class OrderController extends Controller
{
    use CalculateOrderDataTrait;
    public function __construct(
        private Order           $order,
        private User            $user,
        private BusinessSetting $business_setting,
        private CustomerAddress $customer_addresses,
        private OrderArea $orderArea,
        private Product        $product,
    ){}

    /**
     * @param $status
     * @param Request $request
     * @return Renderable
     */
    public function list($status, Request $request): Renderable
    {
        Helpers::update_daily_product_stock();

        $from = $request['from'];
        $to = $request['to'];

        $this->order->where(['checked' => 0, 'branch_id' => auth('branch')->id()])->update(['checked' => 1]);

        if ($status == 'all') {
            $orders = $this->order
                ->with(['customer'])
                ->where(['branch_id' => auth('branch')->id()]);

        } elseif ($status == 'schedule') {
            $orders = $this->order
                ->whereDate('delivery_date', '>', \Carbon\Carbon::now()->format('Y-m-d'))
                ->where(['branch_id' => auth('branch')->id()]);

        } else {
            $orders = $this->order
                ->with(['customer'])
                ->where(['order_status' => $status, 'branch_id' => auth('branch')->id()])
                ->whereDate('delivery_date', '<=', \Carbon\Carbon::now()->format('Y-m-d'));
        }

        $queryParam = [];
        $search = $request['search'];

        if ($request->has('search')) {
            $key = explode(' ', $request['search']);
            $orders = $this->order
                ->where(['branch_id' => auth('branch')->id()])
                ->whereDate('delivery_date', '<=', Carbon::now()->format('Y-m-d'))
                ->where(function ($q) use ($key) {
                    foreach ($key as $value) {
                        $q->orWhere('id', 'like', "%{$value}%")
                            ->orWhere('order_status', 'like', "%{$value}%")
                            ->orWhere('transaction_reference', 'like', "%{$value}%");
                    }
                });
            $queryParam = ['search' => $request['search']];
        }

        if ($from && $to) {
            $orders = $this->order->whereBetween('created_at', [Carbon::parse($from)->startOfDay(), Carbon::parse($to)->endOfDay()]);
            $queryParam = ['from' => $from, 'to' => $to];
        }

        $orderCount = [
            'pending' => $this->order
                ->notPos()
                ->notSchedule()
                ->where(['order_status' => 'pending', 'branch_id' => auth('branch')->id()])
                ->when(!is_null($from) && !is_null($to), function ($query) use ($from, $to) {
                    $query->whereBetween('created_at', [$from, Carbon::parse($to)->endOfDay()]);
                })->count(),

            'confirmed' => $this->order
                ->notPos()
                ->notSchedule()
                ->where(['order_status' => 'confirmed', 'branch_id' => auth('branch')->id()])
                ->when(!is_null($from) && !is_null($to), function ($query) use ($from, $to) {
                    $query->whereBetween('created_at', [$from, Carbon::parse($to)->endOfDay()]);
                })->count(),

            'processing' => $this->order
                ->notPos()
                ->notSchedule()
                ->where(['order_status' => 'processing', 'branch_id' => auth('branch')->id()])
                ->when(!is_null($from) && !is_null($to), function ($query) use ($from, $to) {
                    $query->whereBetween('created_at', [$from, Carbon::parse($to)->endOfDay()]);
                })->count(),

            'out_for_delivery' => $this->order
                ->notPos()
                ->notSchedule()
                ->where(['order_status' => 'out_for_delivery', 'branch_id' => auth('branch')->id()])
                ->when(!is_null($from) && !is_null($to), function ($query) use ($from, $to) {
                    $query->whereBetween('created_at', [$from, Carbon::parse($to)->endOfDay()]);
                })->count(),

            'delivered' => $this->order
                ->notPos()
                ->notSchedule()
                ->where(['order_status' => 'delivered', 'branch_id' => auth('branch')->id()])
                ->when(!is_null($from) && !is_null($to), function ($query) use ($from, $to) {
                    $query->whereBetween('created_at', [$from, Carbon::parse($to)->endOfDay()]);
                })->count(),

            'canceled' => $this->order
                ->notPos()
                ->notSchedule()
                ->where(['order_status' => 'canceled', 'branch_id' => auth('branch')->id()])
                ->when(!is_null($from) && !is_null($to), function ($query) use ($from, $to) {
                    $query->whereBetween('created_at', [$from, Carbon::parse($to)->endOfDay()]);
                })->count(),

            'returned' => $this->order
                ->notPos()
                ->notSchedule()
                ->where(['order_status' => 'returned', 'branch_id' => auth('branch')->id()])
                ->when(!is_null($from) && !is_null($to), function ($query) use ($from, $to) {
                    $query->whereBetween('created_at', [$from, Carbon::parse($to)->endOfDay()]);
                })->count(),

            'failed' => $this->order
                ->notPos()
                ->notSchedule()
                ->where(['order_status' => 'failed', 'branch_id' => auth('branch')->id()])
                ->when(!is_null($from) && !is_null($to), function ($query) use ($from, $to) {
                    $query->whereBetween('created_at', [$from, Carbon::parse($to)->endOfDay()]);
                })->count(),
        ];

        $orders = $orders->notPos()->notDineIn()->latest()->paginate(Helpers::getPagination())->appends($queryParam);
        session()->put('order_data_export', $orders);

        return view('branch-views.order.list', compact('orders', 'status', 'search', 'from', 'to', 'orderCount'));
    }

    /**
     * @param $id
     * @return Renderable|RedirectResponse
     */
    public function details($id): Renderable|RedirectResponse
    {
        Helpers::update_daily_product_stock();

        $order = $this->order
            ->with(['details','order_partial_payments'])
            ->where(['id' => $id, 'branch_id' => auth('branch')->id()])
            ->first();

        if (!isset($order)) {
            Toastr::info(translate('Order not found!'));
            return back();
        }

        $address = $order->delivery_address ?? CustomerAddress::find($order->delivery_address_id);
        $order->address = $address;

        //remaining delivery time
        $deliveryDateTime = $order['delivery_date'] . ' ' . $order['delivery_time'];
        $orderedTime = Carbon::createFromFormat('Y-m-d H:i:s', date("Y-m-d H:i:s", strtotime($deliveryDateTime)));
        $remainingTime = $orderedTime->add($order['preparation_time'], 'minute')->format('Y-m-d H:i:s');
        $order['remaining_time'] = $remainingTime;

        $orderId = $id;

        return view('branch-views.order.order-view', compact('order', 'orderId'));
    }

    /**
     * @param Request $request
     * @return RedirectResponse
     */
    public function status(Request $request): RedirectResponse
    {
        $order = $this->order
            ->where(['id' => $request->id, 'branch_id' => auth('branch')->id()])
            ->first();

        if (in_array($order->order_status, ['delivered', 'failed'])) {
            Toastr::warning(translate('you_can_not_change_the_status_of '. $order->order_status .' order'));
            return back();
        }

        if ($request->order_status == 'delivered' && $order['transaction_reference'] == null && !in_array($order['payment_method'], ['cash_on_delivery', 'wallet_payment', 'offline_payment'])) {
            Toastr::warning(translate('add_your_payment_reference_first'));
            return back();
        }

        if (($request->order_status == 'delivered' || $request->order_status == 'out_for_delivery') && $order['delivery_man_id'] == null && $order['order_type'] != 'take_away') {
            Toastr::warning(translate('Please assign delivery man first!'));
            return back();
        }

        if ($request->order_status == 'completed' && $order->payment_status != 'paid') {
            Toastr::warning(translate('Please update payment status first!'));
            return back();
        }

        if ($request->order_status == 'delivered') {
            if ($order->is_guest == 0){
                if ($order->user_id) CustomerLogic::create_loyalty_point_transaction($order->user_id, $order->id, $order->order_amount, 'order_place');

                if ($order->transaction == null) {
                    $ol = OrderLogic::create_transaction($order, 'admin');
                }

                $user = $this->user->find($order->user_id);

                if (isset($user)){
                    $referralData = $user?->referral_customer_details;

                    if ($referralData && $referralData->is_used_by_refer == 0) {
                        $referralEarningAmount = $referralData->ref_by_earning_amount ?? 0;
                        $referredByUser = $this->user->find($user->refer_by);

                        if ($referralEarningAmount > 0 && $referredByUser){
                            CustomerLogic::referral_earning_wallet_transaction($order->user_id, 'referral_order_place', $referredByUser->id, $referralEarningAmount);
                        }
                        ReferralCustomer::where('user_id', $order->user_id)->update(['is_used_by_refer' => 1]);
                    }
                }
            }

            if ($order['payment_method'] == 'cash_on_delivery'){
                $partialData = OrderPartialPayment::where(['order_id' => $order->id])->first();
                if ($partialData){
                    $partial = new OrderPartialPayment;
                    $partial->order_id = $order['id'];
                    $partial->paid_with = 'cash_on_delivery';
                    $partial->paid_amount = $partialData->due_amount;
                    $partial->due_amount = 0;
                    $partial->save();
                }
            }
        }

        $order->order_status = $request->order_status;
        if ($request->order_status == 'delivered') {
            $order->payment_status = 'paid';
        }
        $order->save();

        if ($request->order_status == 'out_for_delivery' && $order->delivery_man_id != null) {
            DeliveryHistory::updateOrInsert(
                [
                    'order_id' => $order->id,
                    'deliveryman_id' => $order->delivery_man_id,
                ],
                [
                    'latitude' => $order?->branch?->latitude,
                    'longitude' => $order?->branch?->longitude,
                    'time' => now(),
                    'location' => $order?->branch?->address,
                    'updated_at' => now()
                ]
            );
        }

        $message = Helpers::order_status_update_message($request->order_status);
        $restaurantName = Helpers::get_business_settings('restaurant_name');
        $deliverymanName = $order->delivery_man ? $order->delivery_man->f_name. ' '. $order->delivery_man->l_name : '';
        $customerName = $order->is_guest == 0 ? ($order->customer ? $order->customer->f_name. ' '. $order->customer->l_name : '') : 'Guest User';
        $local = $order->is_guest == 0 ? ($order->customer ? $order->customer->language_code : 'en') : 'en';

        if ($local != 'en'){
            $statusKey = Helpers::order_status_message_key($request->order_status);
            $translatedMessage = $this->business_setting->with('translations')->where(['key' => $statusKey])->first();
            if (isset($translatedMessage->translations)){
                foreach ($translatedMessage->translations as $translation){
                    if ($local == $translation->locale){
                        $message = $translation->value;
                    }
                }
            }
        }

        $value = Helpers::text_variable_data_format(value:$message, user_name: $customerName, restaurant_name: $restaurantName, delivery_man_name: $deliverymanName, order_id: $order->id);

        $customerFcmToken = null;
        if($order->is_guest == 0){
            $customerFcmToken = $order->customer ? $order->customer->cm_firebase_token : null;
        }elseif($order->is_guest == 1){
            $customerFcmToken = $order->guest ? $order->guest->fcm_token : null;
        }

        try {
            if ($value) {
                $data = [
                    'title' => translate('Order'),
                    'description' => $value,
                    'order_id' => $order['id'],
                    'image' => '',
                    'type' => 'order_status',
                ];
                if (isset($customerFcmToken)) {
                    Helpers::send_push_notif_to_device($customerFcmToken, $data);
                }
            }

        } catch (\Exception $e) {
            Toastr::warning(translate('Push notification failed for Customer!'));
        }

        //delivery man notification
        if ($request->order_status == 'processing' || $request->order_status == 'out_for_delivery') {

            if (isset($order->delivery_man)) {
                $deliverymanFcmToken = $order->delivery_man->fcm_token;
            }

            $value = translate('One of your order is on processing');
            $outForDeliveryValue = translate('One of your order is out for delivery');
            try {
                if ($value) {
                    $data = [
                        'title' => translate('Order'),
                        'description' => $request->order_status == 'processing' ? $value : $outForDeliveryValue,
                        'order_id' => $order['id'],
                        'image' => '',
                        'type' => 'order_status',
                    ];
                    if (isset($deliverymanFcmToken)) {
                        Helpers::send_push_notif_to_device(fcm_token: $deliverymanFcmToken, data: $data);
                    }

                }
            } catch (\Exception $e) {
                Toastr::warning(translate('Push notification failed for DeliveryMan!'));
            }
        }

        //kitchen order notification
        if ($request->order_status == 'confirmed') {
            $data = [
                'title' => translate('You have a new order - (Order Confirmed).'),
                'description' => $order->id,
                'order_id' => $order->id,
                'order_status' => $order->order_status,
                'image' => '',
            ];

            try {
                Helpers::send_push_notif_to_topic(data: $data, topic: "kitchen-{$order->branch_id}", type: 'general', isNotificationPayloadRemove: true);

            } catch (\Exception $e) {
                Toastr::warning(translate('Push notification failed!'));
            }
        }

        Toastr::success(translate('Order status updated!'));
        return back();
    }

    /**
     * @param Request $request
     * @param $id
     * @return RedirectResponse
     * @throws \Exception
     */
    public function preparationTime(Request $request, $id): RedirectResponse
    {
        $order = $this->order->with(['customer'])->find($id);
        $deliveryDateTime = $order['delivery_date'] . ' ' . $order['delivery_time'];

        $orderedTime = Carbon::createFromFormat('Y-m-d H:i:s', date("Y-m-d H:i:s", strtotime($deliveryDateTime)));
        $remainingTime = $orderedTime->add($order['preparation_time'], 'minute')->format('Y-m-d H:i:s');

        //if delivery time is not over
        if (strtotime(date('Y-m-d H:i:s')) < strtotime($remainingTime)) {
            $deliveryTime = new DateTime($remainingTime); //time when preparation will be over
            $currentTime = new DateTime(); // time now
            $interval = $deliveryTime->diff($currentTime);
            $remainingMinutes = $interval->i;
            $remainingMinutes += $interval->days * 24 * 60;
            $remainingMinutes += $interval->h * 60;
            $order->preparation_time = 0;
        } else {
            //if delivery time is over
            $deliveryTime = new DateTime($remainingTime);
            $currentTime = new DateTime();
            $interval = $deliveryTime->diff($currentTime);
            $diffInMinutes = $interval->i;
            $diffInMinutes += $interval->days * 24 * 60;
            $diffInMinutes += $interval->h * 60;
            $order->preparation_time = 0;
        }

        $newDeliveryDateTime = Carbon::now()->addMinutes((int) $request->extra_minute);
        $order->delivery_date = $newDeliveryDateTime->format('Y-m-d');
        $order->delivery_time = $newDeliveryDateTime->format('H:i:s');
        $order->save();

        $customer = $order->customer;
        $customerFcmToken = null;
        $customerFcmToken = $customer?->cm_firebase_token;
        $value = Helpers::order_status_update_message('customer_notify_message_for_time_change');

        try {
            if ($value) {
                $data = [
                    'title' => translate('Order'),
                    'description' => $value,
                    'order_id' => $order['id'],
                    'image' => '',
                    'type' => 'order_status',
                ];
                Helpers::send_push_notif_to_device($customerFcmToken, $data);
            } else {
                throw new \Exception(translate('failed'));
            }

        } catch (\Exception $e) {
            Toastr::warning(translate('Push notification send failed for Customer!'));
        }

        Toastr::success(translate('Order preparation time increased'));
        return back();
    }

    /**
     * @param $order_id
     * @param $delivery_man_id
     * @return JsonResponse
     */
    public function addDeliveryman($order_id, $delivery_man_id): JsonResponse
    {
        if ($delivery_man_id == 0) {
            return response()->json([], 401);
        }
        $order = $this->order->where(['id' => $order_id, 'branch_id' => auth('branch')->id()])->first();
        if ($order->order_status == 'pending' || $order->order_status == 'delivered' || $order->order_status == 'returned' || $order->order_status == 'failed' || $order->order_status == 'canceled' || $order->order_status == 'scheduled') {
            return response()->json(['status' => false], 200);
        }
        $order->delivery_man_id = $delivery_man_id;
        $order->save();

        $deliverymanFcmToken = $order->delivery_man->fcm_token;
        $customerFcmToken = null;
        if (isset($order->customer)) {
            $customerFcmToken = $order->customer->cm_firebase_token;
        }
        $value = Helpers::order_status_update_message('del_assign');
        try {
            if ($value) {
                $data = [
                    'title' => translate('Order'),
                    'description' => $value,
                    'order_id' => $order['id'],
                    'image' => '',
                    'type' => 'order_status',
                ];
                Helpers::send_push_notif_to_device(fcm_token: $deliverymanFcmToken, data: $data, isDeliverymanAssigned: true);
            }
        } catch (\Exception $e) {
            Toastr::warning(translate('Push notification failed for DeliveryMan!'));
        }

        Toastr::success(translate('Order deliveryman added!'));
        return response()->json(['status' => true], 200);
    }

    /**
     * @param Request $request
     * @return RedirectResponse
     */
    public function paymentStatus(Request $request): RedirectResponse
    {
        $order = $this->order->where(['id' => $request->id, 'branch_id' => auth('branch')->id()])->first();
        if ($request->payment_status == 'paid' && $order['transaction_reference'] == null && $order['payment_method'] != 'cash_on_delivery' && $order['order_type'] != 'dine_in' && !in_array($order['payment_method'], ['cash_on_delivery', 'wallet_payment', 'offline_payment', 'cash'])) {
            Toastr::warning(translate('Add your payment reference code first!'));
            return back();
        }
        $order->payment_status = $request->payment_status;
        $order->save();

        Toastr::success(translate('Payment status updated!'));
        return back();
    }

    /**
     * @param Request $request
     * @return RedirectResponse
     */
    public function updateShipping(Request $request): RedirectResponse
    {
        $request->validate([
            'contact_person_name' => 'required',
            'address_type' => 'required',
            'contact_person_number' => 'required|min:5|max:20',
            'address' => 'required'
        ]);

        $address = [
            'id' => null,
            'contact_person_name' => $request->contact_person_name,
            'contact_person_number' => $request->contact_person_number,
            'address_type' => $request->address_type,
            'road' => $request->road,
            'house' => $request->house,
            'floor' => $request->floor,
            'address' => $request->address,
            'longitude' => $request->longitude,
            'latitude' => $request->latitude,
        ];

        $this->order->where('id', $request->input('order_id'))->update(['delivery_address' => json_encode($address)]);

        Toastr::success(translate('Address updated!'));
        return back();
    }

    /**
     * @param $id
     * @return Renderable
     */
    public function generateInvoice($id): Renderable
    {
        $order = $this->order->with(['order_partial_payments'])->where(['id' => $id, 'branch_id' => auth('branch')->id()])->first();
        $address = $order->delivery_address ?? CustomerAddress::find($order->delivery_address_id);
        $order->address = $address;
        return view('branch-views.order.invoice', compact('order'));
    }

    /**
     * @param Request $request
     * @param $id
     * @return RedirectResponse
     */
    public function addPaymentReferenceCode(Request $request, $id): RedirectResponse
    {
        $this->order->where(['id' => $id, 'branch_id' => auth('branch')->id()])->update([
            'transaction_reference' => $request['transaction_reference']
        ]);

        Toastr::success(translate('Payment reference code is added!'));
        return back();
    }

    /**
     * @return StreamedResponse|string
     * @throws \Box\Spout\Common\Exception\IOException
     * @throws \Box\Spout\Common\Exception\InvalidArgumentException
     * @throws \Box\Spout\Common\Exception\UnsupportedTypeException
     * @throws \Box\Spout\Writer\Exception\WriterNotOpenedException
     */
    public function exportExcel(): StreamedResponse|string
    {
        $data = [];
        $orders = session('order_data_export');
        foreach ($orders as $key => $order) {
            $data[$key]['SL'] = ++$key;
            $data[$key]['Order ID'] = $order->id;
            $data[$key]['Order Date'] = date('d M Y h:m A', strtotime($order['created_at']));
            $data[$key]['Customer Info'] = $order['user_id'] == null ? 'Walk in Customer' : ($order->customer == null ? 'Customer Unavailable' : $order->customer['f_name'] . ' ' . $order->customer['l_name']);
            $data[$key]['Branch'] = $order->branch ? $order->branch->name : 'Branch Deleted';
            $data[$key]['Total Amount'] = Helpers::set_symbol($order['order_amount']);
            $data[$key]['Payment Status'] = $order->payment_status == 'paid' ? 'Paid' : 'Unpaid';
            $data[$key]['Order Status'] = $order['order_status'] == 'pending' ? 'Pending' : ($order['order_status'] == 'confirmed' ? 'Confirmed' : ($order['order_status'] == 'processing' ? 'Processing' : ($order['order_status'] == 'delivered' ? 'Delivered' : ($order['order_status'] == 'picked_up' ? 'Out For Delivery' : str_replace('_', ' ', $order['order_status'])))));
        };
        return (new FastExcel($data))->download('orders.xlsx');
    }

    /**
     * @param Request $request
     * @return JsonResponse
     */
    public function changeDeliveryTimeDate(Request $request): JsonResponse
    {
        $order = $this->order->where('id', $request->order_id)->first();
        if (!$order) {
            return response()->json(['status' => false]);
        }
        $order->delivery_date = $request->input('delivery_date') ?? $order->delivery_date;
        $order->delivery_time = $request->input('delivery_time') ?? $order->delivery_time;
        $order->save();

        return response()->json(['status' => true]);

    }

    /**
     * @param Request $request
     * @param $status
     * @return Application|Factory|View
     */
    public function offlineOrderList(Request $request, $status): Factory|View|Application
    {
        $search = $request['search'];
        $statusMapping = [
            'pending' => 0,
            'denied' => 2,
        ];

        $status = $statusMapping[$status];

        $orders = $this->order->with(['offline_payment'])
            ->where(['branch_id' => auth('branch')->id(), 'payment_method' => 'offline_payment'])
            ->whereHas('offline_payment', function ($query) use($status){
                $query->where('status', $status);
            })
            ->when($request->has('search'), function ($query) use ($request) {
                $keys = explode(' ', $request['search']);
                return $query->where(function ($query) use ($keys) {
                    foreach ($keys as $key) {
                        $query->where('id', 'LIKE', '%' . $key . '%')
                            ->orWhere('order_status', 'LIKE', "%{$key}%")
                            ->orWhere('payment_status', 'LIKE', "{$key}%");
                    }
                });
            })
            ->latest()
            ->paginate(Helpers::getPagination());

        return view('branch-views.order.offline-payment.list', compact('orders', 'search'));
    }

    /**
     * @param Request $request
     * @return JsonResponse
     */
    public function offlineViewDetails(Request $request): JsonResponse
    {
        $order = $this->order->find($request->id);

        return response()->json([
            'view' => view('branch-views.order.offline-payment.details-quick-view', compact('order'))->render(),
        ]);
    }

    /**
     * @param $order_id
     * @param $status
     * @return JsonResponse
     */
    public function verifyOfflinePayment($order_id, $status): JsonResponse
    {
        $offlineData = OfflinePayment::where(['order_id' => $order_id])->first();
        if (!isset($offlineData)){
            return response()->json(['status' => false], 200);
        }

        $order = Order::find($order_id);
        if (!isset($order)){
            return response()->json(['status' => false], 200);
        }

        if ($order->order_status == 'canceled'){
            return response()->json(['status' => false, 'type' => 'canceled', 'message' => translate('Can not change the offline status when order status is canceled')], 200);
        }

        $offlineData->status = $status;
        $offlineData->save();

        if ($offlineData->status == 1){
            $order->order_status = 'confirmed';
            $order->payment_status = 'paid';
            $order->save();

            $message = Helpers::order_status_update_message('confirmed');
            $local = $order->is_guest == 0 ? ($order->customer ? $order->customer->language_code : 'en') : 'en';;

            if ($local != 'en'){
                $statusKey = Helpers::order_status_message_key('confirmed');
                $translatedMessage = $this->business_setting->with('translations')->where(['key' => $statusKey])->first();
                if (isset($translatedMessage->translations)){
                    foreach ($translatedMessage->translations as $translation){
                        if ($local == $translation->locale){
                            $message = $translation->value;
                        }
                    }
                }
            }
            $restaurantName = Helpers::get_business_settings('restaurant_name');
            $deliverymanName = $order->delivery_man ? $order->delivery_man->f_name. ' '. $order->delivery_man->l_name : '';
            $customerName = $order->is_guest == 0 ? ($order->customer ? $order->customer->f_name. ' '. $order->customer->l_name : '') : '';

            $value = Helpers::text_variable_data_format(value:$message, user_name: $customerName, restaurant_name: $restaurantName, delivery_man_name: $deliverymanName, order_id: $order->id);

            $customerFcmToken = null;
            if($order->is_guest == 0){
                $customerFcmToken = $order->customer ? $order->customer->cm_firebase_token : null;
            }elseif($order->is_guest == 1){
                $customerFcmToken = $order->guest ? $order->guest->fcm_token : null;
            }

            try {
                if ($value && $customerFcmToken != null) {
                    $data = [
                        'title' => translate('Order'),
                        'description' => $value,
                        'order_id' => $order['id'],
                        'image' => '',
                        'type' => 'order_status',
                    ];
                    Helpers::send_push_notif_to_device($customerFcmToken, $data);
                }
            } catch (\Exception $e) {
                //
            }

        }elseif ($offlineData->status == 2){
            $customerFcmToken = null;
            if($order->is_guest == 0){
                $customerFcmToken = $order->customer ? $order->customer->cm_firebase_token : null;
            }elseif($order->is_guest == 1){
                $customerFcmToken = $order->guest ? $order->guest->fcm_token : null;
            }
            if ($customerFcmToken != null) {
                try {
                    $data = [
                        'title' => translate('Order'),
                        'description' => translate('Offline payment is not verified'),
                        'order_id' => $order->id,
                        'image' => '',
                        'type' => 'order',
                    ];
                    Helpers::send_push_notif_to_device($customerFcmToken, $data);
                } catch (\Exception $e) {
                }
            }

        }
        return response()->json(['status' => true], 200);
    }

    public function updateOrderDeliveryArea(Request $request, $order_id)
    {
        $request->validate([
            'selected_area_id' => 'required'
        ]);

        $order = $this->order->find($order_id);
        if (!$order){
            Toastr::warning(translate('order not found'));
            return back();
        }

        if ($order->order_status == 'delivered') {
            Toastr::warning(translate('you_can_not_change_the_area_once_the_order_status_is_delivered'));
            return back();
        }

        $branch = Branch::with(['delivery_charge_setup', 'delivery_charge_by_area'])
            ->where(['id' => $order['branch_id']])
            ->first(['id', 'name', 'status']);

        if ($branch->delivery_charge_setup->delivery_charge_type != 'area') {
            Toastr::warning(translate('this branch selected delivery type is not area'));
            return back();
        }

        $area = DeliveryChargeByArea::where(['id' => $request['selected_area_id'], 'branch_id' => $order->branch_id])->first();
        if (!$area){
            Toastr::warning(translate('Area not found'));
            return back();
        }

        $order->delivery_charge = $area->delivery_charge;
        $order->save();

        $orderArea = $this->orderArea->firstOrNew(['order_id' => $order_id]);
        $orderArea->area_id = $request->selected_area_id;
        $orderArea->save();

        $customerFcmToken = null;
        if($order->is_guest == 0){
            $customerFcmToken = $order->customer ? $order->customer->cm_firebase_token : null;
        }elseif($order->is_guest == 1){
            $customerFcmToken = $order->guest ? $order->guest->fcm_token : null;
        }

        try {
            if ($customerFcmToken != null) {
                $data = [
                    'title' => translate('Order'),
                    'description' => translate('order delivery area updated'),
                    'order_id' => $order['id'],
                    'image' => '',
                    'type' => 'order_status',
                ];
                Helpers::send_push_notif_to_device($customerFcmToken, $data);
            }
        } catch (\Exception $e) {
            //
        }

        Toastr::success(translate('Order delivery area updated successfully.'));
        return back();
    }

    public function editOrder(Request $request, $orderId)
    {
        $sessionKey = 'order_products_' . $orderId;
        $orderProducts = session()->get($sessionKey);

        if (!$orderProducts) {
            $order = Order::with('details')->findOrFail($orderId);
            $orderProducts = $order->details->map(function($detail) {
                return [
                    'id' => $detail->product_id,
                    'name' => $detail->product?->name,
                    'price' => $detail->price,
                    'quantity' => $detail->quantity,
                    'variation' => $detail->variation,
                    'add_on_ids' => json_decode($detail->add_on_ids, true),
                    'add_on_qtys' => json_decode($detail->add_on_qtys, true),
                    'image' => $detail->product?->imageFullPath,
                    'is_new' => 0,
                ];
            })->toArray();

            session()->put($sessionKey, $orderProducts);
        }

        return response()->json([
            'success' => true,
            'view' => view('branch-views.order.partials.order-products-table', compact('orderProducts', 'orderId'))->render(),
        ]);

    }

    public function searchProduct(Request $request): JsonResponse
    {
        $keyword = $request->get('search');
        $order = $this->order->where(['id' => $request->order_id])->first();

        if (!$order){
            return response()->json([
                'success' => false,
                'message' => translate('Order not found'),
            ], 404);
        }

        if ($order->branch_id == null) {
            return response()->json([
                'success' => false,
                'message' => translate('Branch not assigned for this order'),
            ], 400);
        }

        $branchId = $order->branch_id;
        $orderId = $order->id;

        $searchProducts = $this->product->active()
            ->when($keyword, function ($query) use ($keyword) {
                $query->where(function ($query) use ($keyword) {
                    $query->where('name', 'like', "%{$keyword}%")
                        ->orWhere('id', 'like', "%{$keyword}%");
                });
            })
            ->whereHas('b_product', function ($query) use ($branchId) {
                $query->where('branch_id', $branchId)
                    ->where('is_available', 1);
            })
            ->with(['b_product' => function ($query) use ($branchId) {
                $query->where('branch_id', $branchId)
                    ->where('is_available', 1);
            }])
            ->get();

        $sessionProducts = session()->get("order_products_".$orderId, []);

        foreach ($searchProducts as $product) {
            $branchProduct = $product->b_product->first();

            $price = $branchProduct->price ?? $product->price ?? 0;
            $variation = $branchProduct->variations ?? $product->variations;
            $variationCount = count($variation ?? []);

            $discountData = [
                'discount_type' => $branchProduct->discount_type ?? $product->discount_type ?? 'amount',
                'discount' => $branchProduct->discount ?? $product->discount ?? 0,
            ];

            $discount = Helpers::discount_calculate($discountData, $price);
            $finalPrice = max($price - $discount, 0);

            $stockType = $branchProduct->stock_type ?? 'unlimited';
            $stockQty = $branchProduct->stock ?? 0;
            $soldQty = $branchProduct->sold_quantity ?? 0;
            $availableStock = $stockType != 'unlimited' ? max($stockQty - $soldQty, 0) : null;

            $isAdded = collect($sessionProducts)->contains('id', $product->id);

            // Add computed attributes dynamically
            $product->price_computed = $price;
            $product->discount_computed = $discount;
            $product->final_price_computed = $finalPrice;
            $product->stock_type_computed = $stockType;
            $product->available_stock_computed = $availableStock;
            $product->variation_computed = $variation;
            $product->variation_count = $variationCount;
            $product->is_added = $isAdded;
        }

        return response()->json([
            'success' => true,
            'view' => view('branch-views.order.partials.product-search-result', compact('searchProducts', 'orderId', 'branchId'))->render(),
        ]);
    }

    public function addProductToSession(Request $request)
    {
        $orderId = $request->order_id;
        $productId = $request->id;

        $order = $this->order->find($orderId);
        if (!$order) {
            return response()->json(['success' => false, 'message' => 'Order not found']);
        }

        $branchId = $order->branch_id;
        if (!$branchId) {
            return response()->json(['success' => false, 'message' => 'Branch not assigned for this order']);
        }

        $product = $this->product->active()
            ->where('id', $productId)
            ->whereHas('b_product', function ($query) use ($branchId) {
                $query->where('branch_id', $branchId)->where('is_available', 1);
            })
            ->with(['b_product' => function ($query) use ($branchId) {
                $query->where('branch_id', $branchId)->where('is_available', 1);
            }])
            ->first();

        if (!$product) {
            return response()->json(['success' => false, 'message' => 'Product not found or unavailable']);
        }

        $branchProduct = $product->b_product->first();
        $branchProductVariations = $branchProduct->variations ?? [];
        $basePrice = $branchProduct->price ?? $product->price ?? 0;
        $quantity = $request->quantity ?? 1;

        if ($branchProduct && in_array($branchProduct->stock_type, ['daily', 'fixed'])){
            $availableStock = $branchProduct->stock - $branchProduct->sold_quantity;
            if ($availableStock < $quantity) {
                return response()->json(['success' => false, 'message' => 'stock limit exceeded, available stock is '. $availableStock]);
            }
        }

        $variation = [];
        if ($request->has('variations') && count($branchProductVariations)) {
            // Validate variation selections
            foreach ($request->variations as $key => $value) {

                if ($value['required'] == 'on' && !isset($value['values'])) {
                    return response()->json([
                        'data' => 'variation_error',
                        'message' => translate('Please select items from') . ' ' . $value['name'],
                    ]);
                }
                if (isset($value['values']) && $value['min'] != 0 && $value['min'] > count($value['values']['label'])) {
                    return response()->json([
                        'data' => 'variation_error',
                        'message' => translate('Please select minimum ') . $value['min'] . translate(' For ') . $value['name'] . '.',
                    ]);
                }
                if (isset($value['values']) && $value['max'] != 0 && $value['max'] < count($value['values']['label'])) {
                    return response()->json([
                        'data' => 'variation_error',
                        'message' => translate('Please select maximum ') . $value['max'] . translate(' For ') . $value['name'] . '.',
                    ]);
                }
            }

            $variationData = Helpers::get_varient($branchProductVariations, $request->variations);
            $variation = $variationData['variations'];
        }

        if (is_array($variation)) {
            $variation = json_encode($variation);
        } elseif (!is_string($variation)) {
            $variation = "[]";
        }

        $addonIds = [];
        $addonQuantities = [];

        if ($request->has('addon_id')) {
            foreach ($request['addon_id'] as $id) {
                $addonQuantities[] = (int) $request['addon-quantity' . $id];
                $addonIds[] = (int) $id;
            }
        }

        // Prepare product data exactly like order details
        $productData = [
            'id' => $product->id,
            'name' => $product->name,
            'price' => $basePrice,
            'quantity' => $quantity,
            'variation' => $variation,
            'add_on_ids' => $addonIds,
            'add_on_qtys' => $addonQuantities,
            'image' => $product->imageFullPath ?? asset('public/assets/admin/img/160x160/img2.jpg'),
            'is_new' => 1,
        ];

//        $sessionKey = "order_products_" . $orderId;
//        $orderProducts = session()->get($sessionKey, []);
//
//        $orderProducts[] = $productData;
//        session()->put($sessionKey, $orderProducts);
//
//        return response()->json([
//            'success' => true,
//            'message' => 'Product added successfully',
//            'data' => $productData
//        ]);

        $sessionKey = "order_products_" . $orderId;
        $orderProducts = session()->get($sessionKey, []);

        // Normalize variation string for consistent comparison
        $currentVariationJson = is_string($variation) ? $variation : json_encode($variation);
        $existingIndex = null;

        // Look for existing product with the same ID & same variation
        foreach ($orderProducts as $index => $item) {
            $itemVariationJson = is_string($item['variation']) ? $item['variation'] : json_encode($item['variation']);

            if ($item['id'] == $product->id && $itemVariationJson === $currentVariationJson) {
                $existingIndex = $index;
                break;
            }
        }

        if ($existingIndex !== null) {
            // Check stock before increasing
            if ($branchProduct && in_array($branchProduct->stock_type, ['daily', 'fixed'])) {
                $availableStock = $branchProduct->stock - $branchProduct->sold_quantity;
                $newQty = $orderProducts[$existingIndex]['quantity'] + $quantity;

                if ($availableStock < $newQty) {
                    return response()->json([
                        'success' => false,
                        'message' => 'Stock limit exceeded, available stock is ' . $availableStock,
                    ]);
                }
            }

            // Increase existing quantity
            $orderProducts[$existingIndex]['quantity'] += $quantity;
        } else {
            // Add new product entry
            $orderProducts[] = $productData;
        }

        session()->put($sessionKey, $orderProducts);

        return response()->json([
            'success' => true,
            'message' => $existingIndex !== null
                ? 'Quantity updated successfully'
                : 'Product added successfully',
            'data' => $productData,
        ]);

    }

    public function loadVariationModal(Request $request)
    {
        $productId = $request->product_id;
        $branchId = $request->branch_id;
        $orderId = $request->order_id;

        $product = $this->product->active()
            ->where('id', $productId)
            ->whereHas('b_product', function ($query) use ($branchId) {
                $query->where('branch_id', $branchId)->where('is_available', 1);
            })
            ->with(['b_product' => function ($query) use ($branchId) {
                $query->where('branch_id', $branchId)->where('is_available', 1);
            }])
            ->first();

        if (!$product) {
            return response()->json(['success' => false, 'message' => 'Product not found or unavailable']);
        }

        $branchProduct = $product->b_product->first();

        $price = $branchProduct->price ?? $product->price ?? 0;
        $variations = $branchProduct->variations ?? $product->variations;
        $variationCount = count($variation ?? []);

        $discountData = [
            'discount_type' => $branchProduct->discount_type ?? $product->discount_type ?? 'amount',
            'discount' => $branchProduct->discount ?? $product->discount ?? 0,
        ];

        $discount = Helpers::discount_calculate($discountData, $price);
        $finalPrice = max($price - $discount, 0);

        $stockType = $branchProduct->stock_type ?? 'unlimited';
        $stockQty = $branchProduct->stock ?? 0;
        $soldQty = $branchProduct->sold_quantity ?? 0;
        $availableStock = $stockType != 'unlimited' ? max($stockQty - $soldQty, 0) : null;
        $halalStatus = $branchProduct->halal_status;

        $productData = [
            'price' => $price,
            'variations' => $variations,
            'variation_count' => $variationCount,
            'discount' => $discount,
            'final_price' => $finalPrice,
            'stock_type' => $stockType,
            'stock_qty' => $stockQty,
            'sold_qty' => $soldQty,
            'available_stock' => $availableStock,
            'halal_status' => $halalStatus,
        ];

        return response()->json([
            'success' => true,
            'html' => view('branch-views.order.partials.variation-product-modal', compact('product', 'productData', 'branchId', 'orderId'))->render()
        ]);
    }

    public function updateProductQuantity(Request $request)
    {
        $orderId = $request->order_id;
        $productId = $request->product_id;
        $action = $request->action; // "increase" or "decrease"
        $newQuantity = $request->new_quantity ?? null;

        $product = $this->product->active()
            ->with('b_product')
            ->where('id', $productId)
            ->first();

        if (!$product) {
            return response()->json(['success' => false, 'message' => 'Product not found or unavailable']);
        }

        $branchProduct = $product->b_product->first();
        $sessionKey = "order_products_" . $orderId;
        $orderProducts = session()->get($sessionKey, []);

        foreach ($orderProducts as &$item) {
            if ($item['id'] == $productId) {
                if ($newQuantity) {
                    $updatedQuantity = (int) $newQuantity;
                } elseif ($action === 'increase') {
                    $updatedQuantity = $item['quantity'] + 1;
                } elseif ($action === 'decrease' && $item['quantity'] > 1) {
                    $updatedQuantity = $item['quantity'] - 1;
                } else {
                    $updatedQuantity = $item['quantity'];
                }

                // Stock check
                if ($branchProduct && in_array($branchProduct->stock_type, ['daily', 'fixed'])) {
                    $availableStock = $branchProduct->stock - $branchProduct->sold_quantity;
                    if ($updatedQuantity > $availableStock) {
                        return response()->json([
                            'success' => false,
                            'message' => 'Stock limit exceeded, available stock is ' . $availableStock
                        ]);
                    }
                }

                $item['quantity'] = $updatedQuantity;
                break;
            }
        }

        session()->put($sessionKey, $orderProducts);

        return response()->json([
            'success' => true,
            'message' => 'Quantity updated successfully',
            'products' => $orderProducts,
        ]);
    }

    public function deleteProductFromSession(Request $request)
    {
        $orderId = $request->order_id;
        $index = $request->index;

        $sessionKey = "order_products_" . $orderId;
        $orderProducts = session()->get($sessionKey, []);

        if (count($orderProducts) <= 1) {
            return response()->json([
                'success' => false,
                'message' => 'You cannot delete the last product from the order.'
            ]);
        }

        if (isset($orderProducts[$index])) {
            unset($orderProducts[$index]);
            $orderProducts = array_values($orderProducts); // Reindex array
            session()->put($sessionKey, $orderProducts);

            return response()->json([
                'success' => true,
                'message' => 'Product removed successfully.',
                'products' => $orderProducts
            ]);
        }

        return response()->json([
            'success' => false,
            'message' => 'Invalid product index.'
        ]);
    }

    public function updateEditOrder(Request $request)
    {
        $orderId = $request->order_id;

        $order = $this->order->find($orderId);
        if (!$order) {
            return response()->json(['success' => false, 'message' => translate('Order not found')]);
        }

        if ($order->type == 'pos' &&
            $order->payment_status == 'paid' &&
            !in_array($order->order_status, ['pending', 'confirmed', 'processing']) &&
            ($order->payment_method != 'cash_on_delivery' && $order->order_partial_payments()->exists()))
        {
            return response()->json(['success' => false, 'message' => translate('You can not edit this order')]);
        }

        $sessionKey = "order_products_" . $orderId;
        $cartProducts = session()->get($sessionKey, []);

        if (empty($cartProducts)) {
            return response()->json(['success' => false, 'message' => translate('Cart is empty')]);
        }

        try {
            $amountData = $this->calculateEditOrderAmount(
                cart: $cartProducts,
                order : $order,
            );

        }  catch (ValidationException $e) {
            return response()->json(['errors' => $e->errors()], 403);
        } catch (\Exception $e) {
            DB::rollBack();
            return response()->json(['errors' => [['message' => $e->getMessage()]]], 403);
        }

        try {
            DB::transaction(function () use ($cartProducts, $order, $amountData) {

                $oldOrderAmountWithDeliveryCharge = $order['order_amount'] + $order['delivery_charge'];
                $newOrderAmountWithDeliveryCharge = $amountData['order_amount'] + $amountData['delivery_charge_amount'];

                $order->details()->delete();

                $order->update([
                    'order_amount' => $amountData['order_amount'],
                    'coupon_discount_amount' => $amountData['coupon_discount_amount'],
                    'coupon_code' => $amountData['coupon_code'],
                    'total_tax_amount' => $amountData['total_product_and_addon_tax_amount'],
                    'referral_discount' => $amountData['referral_discount_amount'],
                ]);

                $orderDetails = [];

                foreach ($cartProducts as $cart) {
                    $product = $this->product->find($cart['id']);
                    $branchProduct = ProductByBranch::where([
                        'product_id' => $cart['id'],
                        'branch_id' => $order['branch_id']
                    ])->first();

                    $product->halal_status = $branchProduct?->halal_status ?? 0;

                    if ($branchProduct) {
                        $branchProductVariations = $branchProduct->variations;
                        $variations = [];

                        if (count($branchProductVariations)) {
                            $new = json_decode($cart['variation'], true);

                            foreach ($new as &$item) {
                                if (isset($item['values']) && is_array($item['values'])) {
                                    $item['values'] = [
                                        'label' => array_column($item['values'], 'label')
                                    ];
                                }
                            }
                            unset($item);

                            $variation_data = Helpers::get_varient($branchProductVariations, $new);

                            $price = $branchProduct['price'] + $variation_data['price'];
                            $variations = $variation_data['variations'];
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
                            $new = json_decode($cart['variation'], true);

                            foreach ($new as &$item) {
                                if (isset($item['values']) && is_array($item['values'])) {
                                    $item['values'] = [
                                        'label' => array_column($item['values'], 'label')
                                    ];
                                }
                            }
                            unset($item);

                            $variation_data = Helpers::get_varient($productVariations, $cart['variation']);
                            $price = $product['price'] + $variation_data['price'];
                            $variations = $variation_data['variations'];
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
                    $addonQuantities = $cart['add_on_qtys'] ?? [];
                    $addonIds = $cart['add_on_ids'] ?? [];
                    $addonPrices = [];
                    $addonTaxes = [];

                    foreach($addonIds as $key =>$id){
                        $addon = AddOn::find($id);
                        $addonPrices[] = $addon['price'];
                        $addonTaxes[] = ($addon['price']*$addon['tax']) / 100;
                    }

                    $totalAddonTax = array_reduce(
                        array_map(function ($a, $b) {
                            return $a * $b;
                        }, $addonQuantities, $addonTaxes),
                        function ($carry, $item) {
                            return $carry + $item;
                        },
                        0
                    );
                    /*calculation for addon and addon tax end*/

                    $orderDetails[] = [
                        'order_id' => $order->id,
                        'product_id' => $cart['id'],
                        'product_details' => $product,
                        'quantity' => $cart['quantity'],
                        'price' => $price,
                        'tax_amount' => Helpers::new_tax_calculate($product, $price, $discountData),
                        'discount_on_product' => $discountOnProduct,
                        'discount_type' => 'discount_on_product',
                        'variant' => json_encode([]),
                        'variation' => json_encode($variations),
                        'add_on_ids' => json_encode($cart['add_on_ids']),
                        'add_on_qtys' => json_encode($cart['add_on_qtys']),
                        'add_on_prices' => json_encode($addonPrices),
                        'add_on_taxes' => json_encode($addonTaxes),
                        'add_on_tax_amount' => $totalAddonTax,
                        'created_at' => now(),
                        'updated_at' => now()
                    ];

                    $this->product->find($cart['id'])->increment('popularity_count');

                    //daily and fixed stock quantity update
                    if ($branchProduct && in_array($branchProduct->stock_type, ['daily', 'fixed'])) {
                        $branchProduct->sold_quantity += $cart['quantity'];
                        $branchProduct->save();
                    }
                }

                OrderDetail::insert($orderDetails);

                // edit order amount wallet adjust
//                if ($order['payment_method'] == 'wallet_payment') {
//                    $this->editOrderWalletAdjustment(
//                        order: $order,
//                        newOrderAmountWithDeliveryCharge: $newOrderAmountWithDeliveryCharge,
//                        oldOrderAmountWithDeliveryCharge:  $oldOrderAmountWithDeliveryCharge
//                    );
//                }

            });

            session()->forget("order_products_" . $orderId);

            $this->orderEmailAndNotification(order : $order);

            return response()->json(['success' => true, 'message' => 'Order updated successfully']);

        } catch (\Throwable $e) {
            return response()->json(['errors' => [['message' => $e->getMessage()]]], 403);
        }

    }

    private function orderEmailAndNotification($order)
    {
        $email = null;
        if ($order['is_guest'] == 0){
            $user = User::find($order['user_id']);
            $fcmToken = $user?->cm_firebase_token;
            $email = $user?->email;
            $local = $user?->language_code;
            $customerName = $user?->f_name . ' '. $user?->l_name;
        }else{
            $guest = GuestUser::find($order['user_id']);
            $fcmToken = $guest ? $guest->fcm_token : '';
            $local = 'en';
            $customerName = 'Guest User';
        }

        $message = Helpers::order_status_update_message('order_edit_message');

        if ($local != 'en'){
            $translatedMessage = $this->business_setting->with('translations')->where(['key' => 'order_edit_message'])->first();
            if (isset($translatedMessage->translations)){
                foreach ($translatedMessage->translations as $translation){
                    if ($local == $translation->locale){
                        $message = $translation->value;
                    }
                }
            }
        }
        $restaurantName = Helpers::get_business_settings('restaurant_name');
        $value = Helpers::text_variable_data_format(value:$message, user_name: $customerName, restaurant_name: $restaurantName,  order_id: $order['id']);

        try {
            if ($value && isset($fcmToken)) {
                $data = [
                    'title' => translate('Order'),
                    'description' => $value,
                    'order_id' => $order['is_guest'] == 0 ? $order['id'] : null,
                    'image' => '',
                    'type' => 'order_status',
                ];
                Helpers::send_push_notif_to_device($fcmToken, $data);
            }
        } catch (\Exception $e) {
            //
        }

        try {
            $emailServices = Helpers::get_business_settings('mail_config');
            $orderMailStatus = Helpers::get_business_settings('place_order_mail_status_user');
            if (isset($emailServices['status']) && $emailServices['status'] == 1 && $orderMailStatus == 1 && $order['is_guest'] == 0 && $email != null) {
                Mail::to($email)->send(new \App\Mail\OrderPlaced($order['id']));
            }
        }catch (\Exception $e) {
            //
        }

        try {
            $data = [
                'title' => translate('New Order Notification'),
                'description' => translate('An Order is updated, Check Please'),
                'order_id' => $order['id'],
                'image' => '',
                'type' => 'new_order_admin',
            ];

            Helpers::send_push_notif_to_topic(data: $data, topic: 'admin_message', type: 'order_request', web_push_link: route('admin.orders.list',['status'=>'all']));
        }catch (\Exception $exception){
            //
        }
    }


    public function clearAllOrderEditProductSessions()
    {
        $allSessions = session()->all();

        foreach ($allSessions as $key => $value) {
            if (str_starts_with($key, 'order_products_')) {
                session()->forget($key);
            }
        }

        return true;
    }
}
