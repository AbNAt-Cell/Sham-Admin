<?php

namespace App\Http\Controllers\Api\V1;

use App\CentralLogics\Helpers;
use App\Http\Controllers\Controller;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Validator;

class MapApiController extends Controller
{
    /**
     * @param Request $request
     * @return array|JsonResponse|mixed
     */
    public function placeApiAutoComplete(Request $request): mixed
    {
        $validator = Validator::make($request->all(), [
            'search_text' => 'required',
        ]);

        if ($validator->errors()->count() > 0) {
            return response()->json(['errors' => Helpers::error_processor($validator)], 403);
        }

        $apiKey = Helpers::get_business_settings('map_api_server_key');
//      $response = Http::get('https://maps.googleapis.com/maps/api/place/autocomplete/json?input=' . $request['search_text'] . '&key=' . $apiKey);

        $url = 'https://places.googleapis.com/v1/places:autocomplete';
        $data = [
            'input' => $request->input('search_text'),
        ];

        // API Headers
        $headers = [
            'Content-Type' => 'application/json',
            'X-Goog-Api-Key' => $apiKey,
            'X-Goog-FieldMask' => '*'
        ];

        // Send POST request
        $response = Http::withHeaders($headers)->post($url, $data);
        return $response->json();
    }

    /**
     * @param Request $request
     * @return array|JsonResponse|mixed
     */
    public function distanceApi(Request $request): mixed
    {
        $validator = Validator::make($request->all(), [
            'origin_lat' => 'required',
            'origin_lng' => 'required',
            'destination_lat' => 'required',
            'destination_lng' => 'required',
        ]);

        if ($validator->errors()->count() > 0) {
            return response()->json(['errors' => Helpers::error_processor($validator)], 403);
        }

        $apiKey = Helpers::get_business_settings('map_api_server_key');
        $url = 'https://routes.googleapis.com/distanceMatrix/v2:computeRouteMatrix';

        $origin = [
            "waypoint" => [
                "location" => [
                    "latLng" => [
                        "latitude" =>  $request['origin_lat'],
                        "longitude" => $request['origin_lng']
                    ]
                ]
            ]
        ];

        $destination = [
            "waypoint" => [
                "location" => [
                    "latLng" => [
                        "latitude" => $request['destination_lat'],
                        "longitude" => $request['destination_lng']
                    ]
                ]
            ]
        ];

        $data = [
            "origins" => $origin,
            "destinations" => $destination,
            "travelMode" => "DRIVE",
            "routingPreference" => "TRAFFIC_AWARE"
        ];

        // API Headers
        $headers = [
            'Content-Type' => 'application/json',
            'X-Goog-Api-Key' => $apiKey,
            'X-Goog-FieldMask' => '*'
        ];

        // Send POST request
        $response = Http::withHeaders($headers)->post($url, $data);
        return $response->json();
    }

    /**
     * @param Request $request
     * @return array|JsonResponse|mixed
     */
    public function placeApiDetails(Request $request): mixed
    {
        $validator = Validator::make($request->all(), [
            'placeid' => 'required',
        ]);

        if ($validator->errors()->count() > 0) {
            return response()->json(['errors' => Helpers::error_processor($validator)], 403);
        }

        $apiKey = Helpers::get_business_settings('map_api_server_key');
       // $response = Http::get('https://maps.googleapis.com/maps/api/place/details/json?placeid=' . $request['placeid'] . '&key=' . $apiKey);

        $url = 'https://places.googleapis.com/v1/places/'.  $request['placeid'];

        // API Headers
        $headers = [
            'Content-Type' => 'application/json',
            'X-Goog-Api-Key' => $apiKey,
            'X-Goog-FieldMask' => '*'
        ];

        // Send POST request
        $response = Http::withHeaders($headers)->get($url);
        return $response->json();
    }

    /**
     * @param Request $request
     * @return array|JsonResponse|mixed
     */
    public function geocodeApi(Request $request): mixed
    {
        $validator = Validator::make($request->all(), [
            'lat' => 'required',
            'lng' => 'required',
        ]);

        if ($validator->errors()->count() > 0) {
            return response()->json(['errors' => Helpers::error_processor($validator)], 403);
        }

        $apiKey = Helpers::get_business_settings('map_api_server_key');
        $response = Http::get('https://maps.googleapis.com/maps/api/geocode/json?latlng=' . $request->lat . ',' . $request->lng . '&key=' . $apiKey);

        return $response->json();
    }
}
