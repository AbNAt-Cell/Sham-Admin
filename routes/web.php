<?php

use App\Model\Order;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\SslCommerzPaymentController;
use App\Http\Controllers\StripePaymentController;
use App\Http\Controllers\PaypalPaymentController;
use App\Http\Controllers\RazorPayController;
use App\Http\Controllers\SenangPayController;
use App\Http\Controllers\PaystackController;
use App\Http\Controllers\PaymobController;
use App\Http\Controllers\FlutterwaveController;
use App\Http\Controllers\BkashPaymentController;
use App\Http\Controllers\MercadoPagoController;
use App\Http\Controllers\FirebaseController;
use App\Http\Controllers\HomeController;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\View;
use Mpdf\Mpdf;

/**
 * Admin login
 */
Route::get('/', function () {
    return redirect(\route('admin.dashboard'));
});

Route::get('/image-proxy', function () {
    $url = request('url');
    if (!$url) {
        abort(400, 'Missing url parameter');
    }

    $response = Http::withHeaders([
        'User-Agent' => 'Laravel-Image-Proxy'
    ])->get($url);

    return response($response->body(), $response->status())
        ->header('Content-Type', $response->header('Content-Type'))
        ->header('Access-Control-Allow-Origin', '*');
});

Route::post('/subscribeToTopic', [FirebaseController::class, 'subscribeToTopic']);

/**
 * Pages
 */
Route::get('about-us', [HomeController::class, 'about_us'])->name('about-us');
Route::get('terms-and-conditions', [HomeController::class, 'terms_and_conditions'])->name('terms-and-conditions');
Route::get('privacy-policy', [HomeController::class, 'privacy_policy'])->name('privacy-policy');
Route::get('return-policy', [HomeController::class, 'return'])->name('return-policy');
Route::get('refund-policy', [HomeController::class, 'refund'])->name('refund-policy');
Route::get('cancellation-policy', [HomeController::class, 'cancellation_policy'])->name('cancellation-policy');

/**
 * Auth
 */
Route::get('authentication-failed', function () {
    $errors = [];
    array_push($errors, ['code' => 'auth-001', 'message' => 'Unauthenticated.']);
    return response()->json([
        'errors' => $errors,
    ], 401);
})->name('authentication-failed');

/**
 * Payment
 */
//Route::group(['prefix' => 'payment-mobile'], function () {
//    Route::get('/', 'PaymentController@payment')->name('payment-mobile');
//    Route::get('set-payment-method/{name}', 'PaymentController@set_payment_method')->name('set-payment-method');
//});

Route::get('payment-success', 'PaymentController@success')->name('payment-success');
Route::get('payment-fail', 'PaymentController@fail')->name('payment-fail');

$is_published = 0;
try {
    $full_data = include('Modules/Gateways/Addon/info.php');
    $is_published = $full_data['is_published'] == 1 ? 1 : 0;
} catch (\Exception $exception) {}

if (!$is_published) {
    Route::group(['prefix' => 'payment'], function () {

        //SSLCOMMERZ
        Route::group(['prefix' => 'sslcommerz', 'as' => 'sslcommerz.'], function () {
            Route::get('pay', [SslCommerzPaymentController::class, 'index'])->name('pay');
            Route::post('success', [SslCommerzPaymentController::class, 'success'])->withoutMiddleware([\App\Http\Middleware\VerifyCsrfToken::class]);
            Route::post('failed', [SslCommerzPaymentController::class, 'failed'])->withoutMiddleware([\App\Http\Middleware\VerifyCsrfToken::class]);
            Route::post('canceled', [SslCommerzPaymentController::class, 'canceled'])->withoutMiddleware([\App\Http\Middleware\VerifyCsrfToken::class]);
        });

        //PAYPAL
        Route::group(['prefix' => 'paypal', 'as' => 'paypal.'], function () {
            Route::get('pay', [PaypalPaymentController::class, 'payment']);
            Route::any('success', [PaypalPaymentController::class, 'success'])->name('success')->withoutMiddleware([\App\Http\Middleware\VerifyCsrfToken::class]);
            Route::any('cancel', [PaypalPaymentController::class, 'cancel'])->name('cancel')->withoutMiddleware([\App\Http\Middleware\VerifyCsrfToken::class]);
        });

        //STRIPE
        Route::group(['prefix' => 'stripe', 'as' => 'stripe.'], function () {
            Route::get('pay', [StripePaymentController::class, 'index'])->name('pay');
            Route::get('token', [StripePaymentController::class, 'payment_process_3d'])->name('token');
            Route::get('success', [StripePaymentController::class, 'success'])->name('success');
        });

        //RAZOR-PAY
        Route::group(['prefix' => 'razor-pay', 'as' => 'razor-pay.'], function () {
            Route::get('pay', [RazorPayController::class, 'index']);
            Route::post('payment', [RazorPayController::class, 'payment'])->name('payment')->withoutMiddleware([\App\Http\Middleware\VerifyCsrfToken::class]);
            Route::post('callback', [RazorPayController::class, 'callback'])->name('callback')->withoutMiddleware([\App\Http\Middleware\VerifyCsrfToken::class]);
            Route::any('cancel', [RazorPayController::class, 'cancel'])->name('cancel')->withoutMiddleware([\App\Http\Middleware\VerifyCsrfToken::class]);
            Route::any('create-order', [RazorPayController::class, 'createOrder'])->name('create-order')->withoutMiddleware([\App\Http\Middleware\VerifyCsrfToken::class]);
            Route::any('verify-payment', [RazorPayController::class, 'verifyPayment'])->name('verify-payment')->withoutMiddleware([\App\Http\Middleware\VerifyCsrfToken::class]);
        });

        //SENANG-PAY
        Route::group(['prefix' => 'senang-pay', 'as' => 'senang-pay.'], function () {
            Route::get('pay', [SenangPayController::class, 'index']);
            Route::any('callback', [SenangPayController::class, 'return_senang_pay']);
        });

        //PAYSTACK
        Route::group(['prefix' => 'paystack', 'as' => 'paystack.'], function () {
            Route::get('pay', [PaystackController::class, 'index'])->name('pay');
            Route::post('payment', [PaystackController::class, 'redirectToGateway'])->name('payment');
            Route::get('callback', [PaystackController::class, 'handleGatewayCallback'])->name('callback');
        });

        //PAYMOB
        Route::group(['prefix' => 'paymob', 'as' => 'paymob.'], function () {
            Route::any('pay', [PaymobController::class, 'credit'])->name('pay');
            Route::any('callback', [PaymobController::class, 'callback'])->name('callback');
        });

        //FLUTTERWAVE
        Route::group(['prefix' => 'flutterwave-v3', 'as' => 'flutterwave-v3.'], function () {
            Route::get('pay', [FlutterwaveController::class, 'initialize'])->name('pay');
            Route::get('callback', [FlutterwaveController::class, 'callback'])->name('callback');
        });

        //BKASH
        Route::group(['prefix' => 'bkash', 'as' => 'bkash.'], function () {
            // Payment Routes for bKash
            Route::get('make-payment', [BkashPaymentController::class, 'make_tokenize_payment'])->name('make-payment');
            Route::any('callback', [BkashPaymentController::class, 'callback'])->name('callback');

            // Refund Routes for bKash
            // Route::get('refund', 'BkashRefundController@index')->name('bkash-refund');
            // Route::post('refund', 'BkashRefundController@refund')->name('bkash-refund');
        });

        //MERCADOPAGO
        Route::group(['prefix' => 'mercadopago', 'as' => 'mercadopago.'], function () {
            Route::get('pay', [MercadoPagoController::class, 'index'])->name('index');
            Route::post('make-payment', [MercadoPagoController::class, 'make_payment'])->name('make_payment');
        });
    });
}

Route::get('order-invoice', function () {
    $order = Order::find(100138); // shorter syntax

    $view = View::make('email-templates.invoice', compact('order'))->render();

    // Create mPDF instance
    $mpdf = new Mpdf([
        'tempDir' => storage_path('tmp'), // safer & Laravel-friendly
        'default_font' => 'dejavusans',        // or 'dejavusans' for ৳ symbol
        'mode' => 'utf-8',
    ]);

    $mpdf->autoScriptToLang = true;
    $mpdf->autoLangToFont = true;

    // Load HTML into PDF
    $mpdf->WriteHTML($view);

    // Download the PDF
    $mpdf->Output('invoice.pdf', 'I'); // 'D' = force download

});
