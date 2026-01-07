@extends('layouts.page-layout')

@section('title', translate('Terms and Conditions'))

@push('css_or_js')
    <style>
        input{
            display: none!important;
        }
    </style>
@endpush

@section('content')
    <div class="row justify-content-center">
        <div class="col-md-12 mt-3">
            <div class="card mt-3">
                <div class="card-header d-flex align-items-center justify-content-center">
                    <h3 class="">{{ translate('Terms and Conditions') }}</h3>
                </div>
                <div class="card-body">
                    {!! \App\Model\BusinessSetting::where(['key'=>'terms_and_conditions'])->first()->value !!}
                </div>
            </div>
        </div>
    </div>
@endsection


@push('script')
    <script>
        $(document).ready(function () {
            document.getElementsByClassName("ql-editor")[0].contentEditable = "false";
        });
    </script>
@endpush
