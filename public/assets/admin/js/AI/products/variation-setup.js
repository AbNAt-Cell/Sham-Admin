$(document).on('click', '.variation_setup_auto_fill', function () {
    const $button = $(this);
    const lang = $button.data('lang');
    const route = $button.data('route');
    const name = $('#' + lang + '_name').val();
    const descriptionId = lang + '_short_description';
    const description = $('.' + descriptionId).val();

    const $container = $('.variation_wrapper').find('.outline-wrapper');

    $container.addClass('outline-animating');
    $container.find('.bg-animate').addClass('active');
    $button.prop('disabled', true);
    $button.find('.btn-text').text('');
    const $aiText = $button.find('.ai-text-animation');
    $aiText.removeClass('d-none').addClass('ai-text-animation-visible');



    $.ajax({
        url: route,
        type: 'GET',
        dataType: 'json',
        data: {
            name: name,
            description: description,
        },
        success: function (response) {
            console.log(response)

            //remove previous ai generated variation
            $('#add_new_option').empty();

            scrollServiceDescriptionWrapperElement(200);


            const data = response.data || {};
            const variations = response.data?.variations || [];

            variations.forEach((variation, index) => {
                // Create variation card
                const count = index + 1; // unique count for IDs
                let add_option_view = `
                <div class="card view_new_option mb-2 ai-generated-variation">
                    <div class="card-header">
                        <label id="new_option_name_${count}">${variation.name}</label>
                    </div>
                    <div class="card-body">
                        <div class="row g-2">
                            <div class="col-lg-3 col-md-6">
                                <label>Name</label>
                                <input required name="options[${count}][name]" class="form-control" type="text"
                                       value="${variation.name}" onkeyup="new_option_name(this.value, ${count})">
                            </div>

                            <div class="col-lg-3 col-md-6">
                                <div class="form-group">
                                    <label class="input-label">Selection Type</label>
                                    <div class="resturant-type-group border cmn_focus">
                                        <label class="form-check form--check mr-2 mr-md-4">
                                            <input class="form-check-input" type="radio"
                                                   value="multi" name="options[${count}][type]"
                                                   ${variation.type === 'multi' ? 'checked' : ''}
                                                   onchange="show_min_max(${count})">
                                            <span class="form-check-label">Multiple</span>
                                        </label>
                                        <label class="form-check form--check mr-2 mr-md-4">
                                            <input class="form-check-input" type="radio"
                                                   value="single" name="options[${count}][type]"
                                                   ${variation.type === 'single' ? 'checked' : ''}
                                                   onchange="hide_min_max(${count})">
                                            <span class="form-check-label">Single</span>
                                        </label>
                                    </div>
                                </div>
                            </div>

                            <div class="col-12 col-lg-6">
                                <div class="row g-2 align-items-end">
                                    <div class="col-sm-6 col-md-4 min-max-wrapper">
                                        <label>Min</label>
                                        <input id="min_max1_${count}" required name="options[${count}][min]"
                                               class="form-control" type="number" min="1" value="${variation.type === 'multi' ? variation.min : ''}">
                                    </div>
                                    <div class="col-sm-6 col-md-4 min-max-wrapper">
                                        <label>Max</label>
                                        <input id="min_max2_${count}" required name="options[${count}][max]"
                                               class="form-control" type="number" min="1" value="${variation.type === 'multi' ? variation.max : ''}">
                                    </div>
                                    <div class="col-md-4">
                                        <div class="d-flex align-items-center justify-content-between">
                                            <div>
                                                <input id="options[${count}][required]"
                                                       name="options[${count}][required]" type="checkbox"
                                                       ${variation.required ? 'checked' : ''}>
                                                <label for="options[${count}][required]" class="m-0">Required</label>
                                            </div>
                                            <div>
                                                <button type="button" class="btn btn-danger btn-sm delete_input_button"
                                                        onclick="removeOption(this)" title="Delete">
                                                    <i class="tio-add-to-trash"></i>
                                                </button>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <div id="option_price_${count}">
                            <div class="border rounded p-3 pb-0 mt-3">
                                <div id="option_price_view_${count}"></div>
                                <div class="row mt-3 p-3 d-flex" id="add_new_button_${count}">
                                    <button type="button" class="btn btn-outline-primary cmn_focus"
                                            onclick="add_new_row_button(${count})">Add New Option</button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>`;

                $("#add_new_option").append(add_option_view);

                // Append values inside the variation
                variation.values.forEach((val, valIndex) => {
                    const valueRow = `
                    <div class="row add_new_view_row_class mb-3 position-relative pt-3 pt-sm-0 ai-generated-variation-option align-items-end">
                        <div class="col-md-4 col-sm-5">
                            <label>Option Name</label>
                            <input class="form-control" required type="text"
                                   name="options[${count}][values][${valIndex}][label]"
                                   value="${val.label}">
                        </div>
                        <div class="col-md-4 col-sm-5">
                            <label>Additional Price</label>
                            <input class="form-control" required type="number" min="0" step="0.01"
                                   name="options[${count}][values][${valIndex}][optionPrice]"
                                   value="${val.optionPrice}">
                        </div>
                        <div class="col-sm-2 max-sm-absolute">
                            <div class="mt-1">
                                <button type="button" class="btn btn-danger btn-sm" onclick="deleteRow(this)" title="Delete">
                                    <i class="tio-add-to-trash"></i>
                                </button>
                            </div>
                        </div>
                    </div>`;
                    $(`#option_price_view_${count}`).append(valueRow);
                });

                if (variation.type === 'single') {
                    hide_min_max(count);
                } else {
                    show_min_max(count);
                }
            });
        },
        error: function (xhr, status, error) {
            if (xhr.responseJSON && xhr.responseJSON.errors) {
                Object.values(xhr.responseJSON.errors).forEach(errorArray => {
                    errorArray.forEach(errorMsg => {
                        toastr.error(errorMsg);
                    });
                });
            }else if(xhr.responseJSON.message) {
                toastr.error(xhr.responseJSON.message);
            } else {
                toastr.error('An unexpected error occurred.');
            }
        },
        complete: function () {

            setTimeout(function () {
                $container.removeClass('outline-animating');
                $container.find('.bg-animate').removeClass('active');
            }, 500);


            $button.prop('disabled', false);
            $button.find('.btn-text').text('Re-generate');
            $aiText.addClass('d-none').removeClass('ai-text-animation-visible');
            scrollServiceDescriptionWrapperElement(500);

            $('#analyzeImageBtn').prop('disabled', false);
            $('#analyzeImageBtn').find('.btn-text').text('Generate Product');
            $('#analyzeImageBtn').find('.ai-btn-animation').addClass('d-none');
            $('#analyzeImageBtn').find('i').removeClass('d-none');
            $('#chooseImageBtn').removeClass('disabled');

            setTimeout(function () {
                $('#aiAssistantModal').modal('hide');
            }, 1000);

        }
    });
});
