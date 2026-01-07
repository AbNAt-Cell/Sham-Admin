$(document).on('click', '.addon_setup_auto_fill', function () {
    const $button = $(this);
    const lang = $button.data('lang');
    const route = $button.data('route');
    const name = $('#' + lang + '_name').val();
    const descriptionId = lang + '_short_description';
    const description = $('.' + descriptionId).val();

    const $container = $('.addon_wrapper').find('.outline-wrapper');

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
            const data = response.data || {};

            const addonNames = data.addon_name || [];

            $('#choose_addons').val(null).trigger('change');

            if (Array.isArray(addonNames) && addonNames.length > 0) {
                addonNames.forEach(function (addonName) {
                    $('#choose_addons option').each(function () {
                        if ($(this).text().trim().toLowerCase() === addonName.trim().toLowerCase()) {
                            $(this).prop('selected', true);
                        }
                    });
                });
                $('#choose_addons').trigger('change');
            }

            if ($button.data('next-action')?.toString() === 'tags-setup') {
                scrollServiceDescriptionWrapperElement(200);

            }

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

            if ($button.data('next-action')?.toString() === 'tags-setup') {
                setTimeout(function () {
                    const target = document.querySelector('.search_tag_setup_auto_fill');
                    if (target) {
                        target.setAttribute('data-next-action', 'cuisine-setup');
                        target.click();
                    }
                }, 2000);
            }


            $button.removeAttr('data-next-action');         // removes HTML attribute
            $button.removeData('next-action');              // removes jQuery cached data
            if ($button[0] && $button[0].dataset) {
                delete $button[0].dataset.nextAction;       // removes DOM dataset property
            }

            setTimeout(function () {
                $container.removeClass('outline-animating');
                $container.find('.bg-animate').removeClass('active');
            }, 500);

            $button.prop('disabled', false);
            $button.find('.btn-text').text('Re-generate');
            $aiText.addClass('d-none').removeClass('ai-text-animation-visible');
        }
    });
});
