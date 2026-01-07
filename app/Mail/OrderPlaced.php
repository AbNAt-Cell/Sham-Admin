<?php

namespace App\Mail;

use App\CentralLogics\Helpers;
use App\Model\BusinessSetting;
use App\Model\CustomerAddress;
use App\Models\EmailTemplate;
use App\Model\Order;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Mail\Mailable;
use Illuminate\Queue\SerializesModels;
use Mpdf\Mpdf;
use Illuminate\Support\Facades\View;


class OrderPlaced extends Mailable
{
    use Queueable, SerializesModels;

    /**
     * Create a new message instance.
     *
     * @return void
     */
    protected $order_id;

    public function __construct($order_id)
    {
        $this->order_id = $order_id;
    }

    /**
     * Build the message.
     *
     * @return $this
     */
    public function build()
    {
        $order_id = $this->order_id;
        $order=Order::where('id', $order_id)->first();

        $address = $order->delivery_address ?? CustomerAddress::find($order->delivery_address_id);
        $order->address = $address;

        $company_name = BusinessSetting::where('key', 'restaurant_name')->first()->value;
        $data=EmailTemplate::with('translations')->where('type','user')->where('email_type', 'new_order')->first();
        $template=$data?$data->email_template:3;
        $user_name = $order?->customer?->f_name.' '.$order?->customer?->l_name;
        $restaurant_name = $order?->branch->name;
        $delivery_man_name = $order?->delivery_man?->f_name.' '.$order?->delivery_man?->l_name;

        $local = $order?->customer->language_code ?? 'en';

        $content = [
            'title' => $data->title,
            'body' => $data->body,
            'footer_text' => $data->footer_text,
            'copyright_text' => $data->copyright_text
        ];

        if ($local != 'en'){
            if (isset($data->translations)){
                foreach ($data->translations as $translation){
                    if ($local == $translation->locale){
                        $content[$translation->key] = $translation->value;
                    }
                }
            }
        }

        $title = Helpers::text_variable_data_format( value:$data['title']??'',user_name:$user_name??'',restaurant_name:$restaurant_name??'',delivery_man_name:$delivery_man_name??'',order_id:$order_id??'');
        $body = Helpers::text_variable_data_format( value:$data['body']??'',user_name:$user_name??'',restaurant_name:$restaurant_name??'',delivery_man_name:$delivery_man_name??'',order_id:$order_id??'');
        $footer_text = Helpers::text_variable_data_format( value:$data['footer_text']??'',user_name:$user_name??'',restaurant_name:$restaurant_name??'',delivery_man_name:$delivery_man_name??'',order_id:$order_id??'');
        $copyright_text = Helpers::text_variable_data_format( value:$data['copyright_text']??'',user_name:$user_name??'',restaurant_name:$restaurant_name??'',delivery_man_name:$delivery_man_name??'',order_id:$order_id??'');

        // **🔹 Generate Invoice PDF**
//        $pdf = Facade\Pdf::loadView('email-templates.invoice', compact('order'));
//        $pdfContent = $pdf->output(); // Get PDF as raw content
//
//        return $this->subject(translate('Order_Place_Mail'))
//            ->view('email-templates.new-email-format-'.$template,
//                ['company_name' => $company_name,
//                    'data' => $data,
//                    'title' => $title,
//                    'body' => $body,
//                    'footer_text' => $footer_text,
//                    'copyright_text' => $copyright_text,
//                    'order' => $order
//                ])
//            ->attachData($pdfContent, 'Invoice_Order_' . $order->id . '.pdf', [
//                'mime' => 'application/pdf',
//            ]);

        $view = View::make('email-templates.invoice', compact('order'))->render();

        $mpdf = new Mpdf([
            'tempDir' => storage_path('tmp'),
            'default_font' => 'dejavusans',
            'mode' => 'utf-8',
        ]);

        $mpdf->autoScriptToLang = true;
        $mpdf->autoLangToFont = true;

        $mpdf->WriteHTML($view);
        $pdfContent = $mpdf->Output('', 'S');

        return $this->subject(translate('Order_Place_Mail'))
            ->view('email-templates.new-email-format-' . $template, [
                'company_name' => $company_name,
                'data' => $data,
                'title' => $title,
                'body' => $body,
                'footer_text' => $footer_text,
                'copyright_text' => $copyright_text,
                'order' => $order
            ])
            ->attachData($pdfContent, 'Invoice_Order_' . $order->id . '.pdf', [
                'mime' => 'application/pdf',
            ]);
    }
}
