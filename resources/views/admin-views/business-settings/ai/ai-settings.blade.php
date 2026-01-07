@extends('layouts.admin.app')

@section('title', translate('AI_Settings'))

@section('content')
    <div class="content container-fluid">
        <div class="d-flex flex-wrap gap-2 align-items-center mb-4">
            <h2 class="h1 mb-0 d-flex align-items-center gap-2">
                <img width="18" height="18" class="svg" src="{{ asset(path: 'public/assets/admin/img/ai/ai-nav-icon.svg') }}" alt="">

                <span class="page-header-title">
                    {{translate('AI_Setup')}}
                </span>
            </h2>
        </div>

        <form action="{{env('APP_MODE')!='demo'?route('admin.ai-settings.update'):'javascript:'}}" method="post">
            @csrf
            <div class="card">
                <div class="card-body">
                    <div class="d-flex flex-wrap justify-content-between align-items-center">
                        <div class="">
                            <h3>{{translate('AI_Configuration')}}</h3>
                            <p class="fz-12 mb-0">{{translate('Fill up the necessary info to activate AI feature.')}}</p>
                        </div>
                        <div class="">
                            <label class="switcher ml-auto mb-0">
                                <input type="checkbox"
                                       name="status"
                                       id="{{ env('APP_MODE') == 'demo' ? 'call-demo' : 'show-global-confirmation-modal' }}"
                                       class="switcher_input"
                                       data-on-image="{{ asset('public/assets/admin/img/icons/status-on.png') }}"
                                       data-off-image="{{ asset('public/assets/admin/img/icons/status-off.png') }}"
                                        {{ isset($data['status']) && $data['status'] == 1 ? 'checked' : '' }}>
                                <span class="switcher_control"></span>
                            </label>
                        </div>
                    </div>

                    <div class="mt-4 p-4 bg-light rounded-10">
                        <div class="row g-4">
                            <div class="col-sm-6">
                                <div class="form-group mb-0">
                                    <label class="text-capitalize">{{translate('Open_AI_Key')}}
                                        <i class="tio-info-outined" data-toggle="tooltip" data-placement="top" title=""
                                           data-original-title="{{ translate('Sign in to OpenAI, create an API key, and use it here.') }}">
                                        </i>
                                    </label>
                                    <input type="text" class="form-control cmn_focus" name="api_key" tabindex="2" placeholder="{{translate('Type API Key')}} *" required="" value="{{env('APP_MODE')!='demo'? $data['api_key'] ?? '' : ''}}">
                                </div>
                            </div>
                            <div class="col-lg-6">
                                <div class="form-group mb-0">
                                    <label class="text-capitalize">{{translate('Open_AI_Organization')}}
                                        <i class="tio-info-outined" data-toggle="tooltip" data-placement="top" title=""
                                           data-original-title="{{ translate('Get your OpenAI Organization ID and enter it here for access and billing.') }}">
                                        </i>
                                    </label>
                                    <input type="text" class="form-control cmn_focus" name="organization_id" placeholder="{{translate('Type Organization Id')}} *" required=""  tabindex="3" value="{{env('APP_MODE')!='demo'? $data['organization_id'] ?? '' : ''}}">
                                </div>
                            </div>
                        </div>

                    </div>
                </div>
            </div>
            <div class="btn--container mt-4">
                <button type="reset" class="btn btn-secondary shadow-none" tabindex="5">{{translate('Reset')}}</button>
                <button type="{{env('APP_MODE')!='demo'?'submit':'button'}}"
                        class="btn btn-primary call-demo" tabindex="6">{{translate('Submit')}}</button>
            </div>
        </form>
    </div>

    {{-- View guideline btn --}}
    <div class="d-flex gap-2 flex-column align-items-center bg-white position-fixed cursor-pointer view-guideline-btn" data-toggle="offcanvas" data-target="#offcanvasSetupGuide">
        <span class="bg-primary p-5px text-white rounded d-flex justify-content-center align-items-center">
            <img src="{{ asset(path: 'public/assets/admin/img/ai/redo.svg') }}" alt="" class="svg" width="10" height="8">
        </span>
        <span class="view-guideline-btn-text text-dark font-weight-medium text-nowrap">
            {{ translate('View_Guideline') }}
        </span>
    </div>

    <div class="offcanvas offcanvas-end" tabindex="-1" id="offcanvasSetupGuide" aria-labelledby="offcanvasSetupGuideLabel">

        <div class="offcanvas-header bg-light d-flex justify-content-between align-items-center gap-3">
            <h3 class="mb-0">{{ translate('AI_Configuration_Guideline') }}</h3>
            <button type="button" class="close fz-20" data-dismiss="offcanvas" aria-label="Close">
                    <span aria-hidden="true">×</span>
            </button>
        </div>

        <div class="offcanvas-body ai-offcanvas-body">
            <div class="p-3 p-sm-4 bg-light rounded mb-3 mb-sm-4">
                <div class="d-flex gap-3 align-items-center justify-content-between overflow-hidden">
                    <button class="btn-collapse d-flex gap-3 align-items-center bg-transparent border-0 p-0" type="button"
                            data-toggle="collapse" data-target="#collapsePurpose" aria-expanded="true">
                        <div class="btn-collapse-icon border bg-light icon-btn rounded-circle text-dark fz-20">
                            <i class="tio-chevron-right"></i>
                        </div>
                        <span class="font-weight-bold text-start">{{ translate('Purpose') }} </span>
                    </button>
                </div>

                <div class="collapse mt-3 show" id="collapsePurpose">
                    <div class="card card-body">
                        <p class="fz-12 mb-0">
                            {{ translate('To_configure_your_preferred_AI_provider_(e.g.,_OpenAI)_by_entering_the_necessary_credentials_and_AI_based_features_like_content_generation_or_image_processing') }}
                        </p>
                    </div>
                </div>
            </div>
            <div class="p-3 p-sm-4 bg-light rounded mb-3 mb-sm-4">
                <div class="d-flex gap-3 align-items-center justify-content-between overflow-hidden">
                    <button class="btn-collapse d-flex gap-3 align-items-center bg-transparent border-0 p-0 collapsed" type="button"
                            data-toggle="collapse" data-target="#collapseAiFeatureToggle" aria-expanded="true">
                        <div class="btn-collapse-icon border bg-light icon-btn rounded-circle text-dark fz-20">
                            <i class="tio-chevron-right"></i>
                        </div>
                        <span class="font-weight-bold text-start">{{ translate('AI_Feature_Toggle') }} </span>
                    </button>
                </div>

                <div class="collapse mt-3" id="collapseAiFeatureToggle">
                    <div class="card card-body">
                        <p class="fz-12">
                            {{ translate('Use_this_switch_to_turn_AI_features_on_or_off_for_your_platform.') }}
                        </p>
                        <ul class="fz-12 mb-0">
                            <li>
                                {{ translate('When_ON') }}: {{ translate('AI_tools_like_content_and_image_generation_will_work.') }}
                            </li>
                            <li>
                                {{ translate('When_OFF') }}: {{ translate('all_AI_features_will_stop_working_until_you_turn_it_back_on.') }}
                            </li>
                        </ul>
                    </div>
                </div>
            </div>
            <div class="p-3 p-sm-4 bg-light rounded mb-3 mb-sm-4">
                <div class="d-flex gap-3 align-items-center justify-content-between overflow-hidden">
                    <button class="btn-collapse d-flex gap-3 align-items-center bg-transparent border-0 p-0 collapsed" type="button"
                            data-toggle="collapse" data-target="#collapseAiFeatureEnableOpenAlConfigurationToggle" aria-expanded="true">
                        <div class="btn-collapse-icon border bg-light icon-btn rounded-circle text-dark fz-20">
                            <i class="tio-chevron-right"></i>
                        </div>
                        <span class="font-weight-bold text-start">{{ translate('Enable OpenAl Configuration') }} </span>
                    </button>
                </div>

                <div class="collapse mt-3" id="collapseAiFeatureEnableOpenAlConfigurationToggle">
                    <div class="card card-body">
                        <ul class="fz-12 mb-0">
                            <li>
                                {{ translate('Go to the OpenAl API platform and') }}
                                <a target="_blank" href="{{ 'https://platform.openai.com/docs/overview' }}">{{ translate('Sign up') }}</a>
                                <span class="px-1">{{ translate('or') }}</span>
                                <a target="_blank" href="{{ 'https://platform.openai.com/docs/overview' }}">{{ translate('Log in.') }}</a>
                            </li>
                            <li>
                                {{ translate('Create a new API key and use it in the OpenAI API key section.') }}
                            </li>
                            <li>
                                {{ translate('Get your OpenAI Organization ID and enter it here for access and billing.') }}
                            </li>
                        </ul>
                    </div>
                </div>
            </div>


            <div class="p-3 p-sm-4 bg-light rounded mb-3 mb-sm-4">
                <div class="d-flex gap-3 align-items-center justify-content-between overflow-hidden">
                    <button class="btn-collapse d-flex gap-3 align-items-center bg-transparent border-0 p-0 collapsed" type="button"
                            data-toggle="collapse" data-target="#collapseTip" aria-expanded="true">
                        <div class="btn-collapse-icon border bg-light icon-btn rounded-circle text-dark fz-20">
                            <i class="tio-chevron-right"></i>
                        </div>
                        <span class="font-weight-bold text-start">{{ translate('Tip') }} </span>
                    </button>
                </div>

                <div class="collapse mt-3" id="collapseTip">
                    <div class="card card-body">
                        <p class="fz-12 mb-0">
                            {{ translate('you_need_to_enter_the_correct_api_details_so_the_AI_tools_(like_text_or_image_generation)_can_work_without_errors.') }}
                        </p>
                    </div>
                </div>
            </div>
        </div>

    </div>

@endsection

@push('script_2')
<script>
    $(document).ready(function () {

        let toggleElement = null;
        let shouldBeChecked = null;
        let modalConfirmed = false;

        $(document).on('change', '#show-global-confirmation-modal', function (e) {
            e.preventDefault();

            toggleElement = $(this);
            shouldBeChecked = toggleElement.prop('checked');
            modalConfirmed = false;

            toggleElement.prop('checked', !shouldBeChecked);

            const dynamicTitle = shouldBeChecked
                ? "{{ translate('Do you want to activate AI feature') }} ?"
                : "{{ translate('Do you want to deactivate AI feature') }} ?";

            const dynamicMessage = shouldBeChecked
                ? "{{ translate('If enabled, AI feature will be active and able to to generate content by AI') }}"
                : "{{ translate('If disabled, AI feature will be inactive and could not able to generate content by AI.') }}";

            const onImage = toggleElement.data('on-image');
            const offImage = toggleElement.data('off-image');

            const image = shouldBeChecked ? onImage : offImage;

            $('#globalConfirmationModalTitle').text(dynamicTitle);
            $('#globalConfirmationModelMessage').text(dynamicMessage);
            $('#globalConfirmationModalImage').attr('src', image);

            $('#globalConfirmationModal').modal('show');
        });

        $('#globalConfirmationModalConfirmButton').on('click', function () {
            if (toggleElement) {
                toggleElement.prop('checked', shouldBeChecked).trigger('change-confirmed');
            }
            modalConfirmed = true;
            $('#globalConfirmationModal').modal('hide');
        });

        $('#globalConfirmationModal').on('hidden.bs.modal', function () {
            if (!modalConfirmed && toggleElement) {
                toggleElement.prop('checked', !shouldBeChecked);
            }
        });

        $(document).on('click', '#call-demo', function (e) {
            e.preventDefault();
            $(this).prop('checked', !$(this).prop('checked'));
            toastr.info('This feature is disabled in demo mode.');
        });

    });
</script>
@endpush
