<!-- AI Assistant Modal -->
<div class="modal fade p-0" id="aiAssistantModal" tabindex="-1" aria-labelledby="aiAssistantModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-sm modal-dialog-slideInRight modal-dialog-scrollable">
        <div class="modal-content bg-white">
            <div class="modal-header d-flex gap-2 aign-items-center justify-content-between">
                <h5 class="modal-title d-flex align-items-center gap-2 aiAssistantModalLabel" id="aiAssistantModalLabel">
                    <span class="square-div">
                        <span class="ai-btn-animation">
                            <span class="gradientCirc"></span>
                        </span>
                        <img class="position-relative z-1" width="15" height="12" src="{{ asset(path: 'public/assets/admin/img/ai/blink-right.svg') }}" alt="">
                    </span>
                    <span id="modalTitle">{{ translate('AI_Assistant') }}</span>
                </h5>
                <div class="d-flex align-items-center gap-2">
                    <button type="button" class="btn btn-circle ai_backBtn" style="display: none;">
                        <i class="tio-arrow-backward"></i>
                    </button>
                    <button type="button" class="btn btn-circle ai-modal-btn" data-dismiss="modal" aria-label="{{ translate('Close') }}">
                        <i class="tio-clear"></i>
                    </button>
                </div>
            </div>
            <div class="modal-body">
                <!-- Main AI Assistant Content -->
                <div id="mainAiContent" class="ai-modal-content">
                    <div class="text-center mb-4">
                        <div class="ai-avatar mb-3">
                            <div class="avatar-circle mx-auto">
                                <span class="ai-btn-animation">
                                    <span class="gradientCirc"></span>
                                </span>
                                <img class="position-relative z-1" width="40" height="34" src="{{ asset(path: 'public/assets/admin/img/ai/blink-right.svg') }}" alt="">
                            </div>
                        </div>

                        <div class="ai-greeting mb-5">
                            <h4 class="text-title">{{ translate('Hi_There') }},</h4>
                            <h2 class="mb-2">{{ translate('I_am_here_to_help_you') }}!</h2>
                            <p class="">
                                {{ translate('i’m_your_personal_assistance_to_easy_your_long_task_smile') }}.
                                {{ translate('just_select_below_how_you_give_me_instruction_to_get_your_product_all_data') }}.
                            </p>
                        </div>

                        <div class="ai-actions d-flex flex-column align-items-center gap-3">
                            <button type="button" class="btn btn-outline-primary image-generate-btn text-dark bg-transparent rounded-10 btn-block max-w-250 d-flex gap-2 ai-action-btn"
                                    data-action="upload">
                                <img width="18" height="18" class="svg" src="{{ asset(path: 'public/assets/admin/img/ai/picture.svg') }}" alt="">
                                <span class="text-title">{{ translate('Upload_Image') }}</span>
                            </button>
                            <button type="button" class="btn bg-light name-generate-btn border text-dark rounded-10 btn-block max-w-250 d-flex gap-2 ai-action-btn"
                                    data-action="title">
                                <img width="18" height="18" class="svg" src="{{ asset(path: 'public/assets/admin/img/ai/text-generate.svg') }}" alt="">
                                <span class="text-title">{{ translate('Generate_Product_Name') }}</span>
                            </button>
                        </div>
                    </div>
                </div>

                <div id="uploadImageContent" class="ai-modal-content h-100" style="display: none;">
                    <div class="d-flex justify-content-center align-items-end w-100 h-100">
                        <div class="">
                            <div class="mb-4">
                                <h4 class="fs-16 fw-bold mb-2">
                                    {{ translate('give_the_product_name_or_upload_image') }}
                                </h4>
                                <p class="mb-3">{{ translate('please_give_proper_product_name_or_image_to_generate_full_data_for_your_product') }}
                                </p>
                                <ul class="d-flex flex-column gap-2 mb-5">
                                    <li>{{ translate('try_to_use_a_clean_&_avoid_blur_image') }}</li>
                                    <li>{{ translate('use_as_close_as_your_product_image') }}</li>
                                </ul>
                            </div>
                            <div class="text-center mb-4">
                                <label class="upload-zone ratio-3-1 max-w-100 w-100 mx-auto rounded-10" id="chooseImageBtn">
                                    <input type="file" id="aiImageUpload" hidden class="d-none image-compressor" accept="image/*">
                                    <input type="file" id="aiImageUploadOriginal" class="d-none" accept="image/*">
                                    <div class="text-box mx-auto">
                                        <div class="w-100 d-flex flex-column gap-2 justify-content-center align-items-center py-4">
                                            <img width="40" height="40" src="{{ asset(path: 'public/assets/admin/img/ai/image-upload.svg') }}"
                                                 alt="">
                                            <div class="d-flex gap-2 align-items-center justify-content-center flex-wrap fs-14">
                                                <span class="text-dark">{{ translate('drag_&_drop_your_image') }}</span>
                                                <span class="text-lowercase">{{ translate('or') }}</span>
                                                <span type="button" class="text-primary font-weight-semibold fz-12 text-decoration-underline">
                                                    {{ translate('Browse_Image') }}
                                                </span>
                                            </div>
                                        </div>
                                    </div>
                                    <div id="imagePreview" class="w-max-content mx-auto position-relative" style="display: none;">
                                        <img id="previewImg" src="" alt="{{ translate('Preview') }}" class="upload-zone_img"
                                             style="max-height: 120px;">
                                        <div class="d-flex justify-content-center gap-2 flex-wrap">
                                            <button type="button" class="btn btn-danger p-0 square-div z-2 fs-10 remove_image_btn" id="removeImageBtn"
                                                    data-toggle="tooltip" title="{{ translate('Remove_image') }}">
                                                <i class="tio-clear"></i>
                                            </button>
                                        </div>
                                    </div>
                                </label>
                                <div class="mt-4 text-center analyzeImageBtn_wrapper">
                                    <button type="button" class="btn btn--primary rounded mb-3 d-flex align-items-center gap-2 opacity-1 border-0 mx-auto position-relative"
                                            id="analyzeImageBtn"
                                            data-url="{{ route('admin.product.analyze-image-auto-fill') }}"
                                            data-lang="en">
                                         <span class="ai-btn-animation d-none">
                                            <span class="gradientRect"></span>
                                        </span>
                                        <span class="position-relative z-1 d-flex gap-2 align-items-center">
                                            <span class="d-flex align-items-center bg-transparent text-white btn-text">{{ translate('Generate_Product') }}</span>
                                            <img width="17" height="15" src="{{ asset(path: 'public/assets/admin/img/ai/blink-left.svg') }}"
                                                 alt="">
                                        </span>
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <div id="giveTitleContent" class="ai-modal-content" style="display: none;">
                    <div class="mb-4">
                        <div class="giveTitleContent_text">
                            <h5 class="mb-3 fs-16 fw-bold text-body lh-base">
                                {{ translate('great!') }}
                                <br>
                                {{ translate('now,_tell_me_which_product_you_want_to_create._just_type_it_simply,_like:') }}
                            </h5>
                            <ul class="d-flex flex-column gap-2 mb-3">
                                <li>{{ translate('i_need_product_details_for_Burger') }}</li>
                                <li>{{ translate('i_want_to_add_a_product_name_briyani') }}</li>
                                <li>{{ translate('i_want_to_create_a_product_name_set_menu') }}</li>
                            </ul>
                            <p class="mb-4">{{ translate('feel_free_to_describe_it_your_own_way!') }}</p>
                        </div>
                        <div class="generate-text-input-group taginput-dark-support">
                            <input type="text" class="form-control" id="productKeywords"
                                   placeholder="{{ translate('Tell_me_about_your_product') }}" data-role="tagsinput">
                            <button type="button" class="btn btn--primary border-0" id="generateTitleBtn"
                                    data-route="{{ route('admin.product.generate-title-suggestions') }}"
                                    data-lang="en">
                                <span class="ai-loader-animation z-2 d-none">
                                    <span class="loader-circle"></span>
                                    <div class="position-relative h-100 d-flex justify-content-center align-items-center">
                                        <img width="15" height="15" class=""
                                             src="{{ asset(path: 'public/assets/admin/img/ai/blink-left.svg') }}" alt="">
                                    </div>
                                </span>
                                <span class="position-rtelative z-1 text-white text-generate-icon">
                                    <i class="tio-arrow-forward"></i>
                                </span>
                            </button>
                        </div>
                    </div>

                    <div id="generatedTitles" style="display: none;">
                        <div class="text-ai generate_btn_wrapper show_generating_text justify-content-start d-none mb-3">
                            <div class="btn-svg-wrapper">
                                <img width="18" height="18" class="" src="{{ asset(path: 'public/assets/admin/img/ai/blink-right-small.svg') }}" alt="">
                            </div>
                            <span class="ai-text-animation ai-text-animation-visible">
                                {{ translate('Just_a_second') }}
                            </span>
                        </div>
                        <h4 class="mb-2 titlesList_title fs-14 fw-bold mb-4 d-none">{{ translate('Suggest_Product_Name') }}</h4>
                        <div id="titlesList" class="list-group gap-4">
                        </div>
                    </div>
                </div>

            </div>

                <div class="modal-footer border-0 justify-content-center">
                    <div class="bg-light px-2 py-1 rounded text-center">
                        <p class="mb-0">{{ translate('AI may make mistakes. please recheck important data.') }}</p>
                    </div>
                </div>
        </div>
    </div>
</div>
