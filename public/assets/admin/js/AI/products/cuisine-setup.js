$(document).on('click', '.cuisine_setup_auto_fill', function () {
    const $button = $(this);
    const lang = $button.data('lang');
    const route = $button.data('route');
    const name = $('#' + lang + '_name').val();
    const descriptionId = lang + '_short_description';
    const description = $('.' + descriptionId).val();

    const $container = $('.cuisine_wrapper').find('.outline-wrapper');

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

            if (response.success && Array.isArray(data.cuisine_name)) {
                const selectedCuisines = data.cuisine_name.map(name => name.toLowerCase());

                const $cuisineSelect = $('select[name="cuisines[]"]');
                $cuisineSelect.find('option').each(function () {
                    const optionText = $(this).text().trim().toLowerCase();
                    $(this).prop('selected', selectedCuisines.includes(optionText));
                });

                $cuisineSelect.trigger('change');
            }

            if ($button.data('next-action')?.toString() === 'variation-setup') {
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

            if ($button.data('next-action')?.toString() === 'variation-setup') {
                setTimeout(function () {
                    const target = document.querySelector('.variation_setup_auto_fill');
                    if (target) {
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
