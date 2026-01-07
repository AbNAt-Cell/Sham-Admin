$(document).on('click', '.auto_fill_short_description', function () {
    const $button = $(this);
    console.log($button);
    console.log($button.data('next-action'));

    const lang = $button.data('lang');
    const route = $button.data('route');
    const itemData = $button.data('item') || {};
    const existingShortDescription = itemData.short_description ?? "";

    const $container = $button.closest('.lang-form');
    const $shortDescription = $container.find('.' + lang + '_short_description');
    const previousValue = $shortDescription.val();
    const name = $('#' + lang + '_name').val() || '';

    console.log(name, $shortDescription, previousValue);

    // Start animation
    $shortDescription.closest('.outline-wrapper').addClass('outline-animating');

    // Disable button + show AI loading animation
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
            langCode: lang
        },
        success: function (response) {
            const plainText = $('<div>').html(response.data).text();
            $('.' + lang + '_short_description').val(plainText);

            console.log("short description above");
            if ($button.data('next-action')?.toString() === 'general-setup') {
                console.log("short description inside", $button.data('next-action')?.toString());
                scrollServiceDescriptionWrapperElement(200);
            }
        },
        error: function (xhr, status, error) {
            $shortDescription.val(existingShortDescription || previousValue);

            if (xhr.responseJSON && xhr.responseJSON.errors) {
                Object.values(xhr.responseJSON.errors).forEach(fieldErrors => {
                    fieldErrors.forEach(errorMessage => {
                        toastr.error(errorMessage);
                    });
                });
            } else if (xhr.responseJSON && xhr.responseJSON.message) {
                toastr.error(xhr.responseJSON.message);
            } else {
                toastr.error('An unexpected error occurred.');
            }
        },
        complete: function () {
            // If this step triggers another AI generation
            if ($button.data('next-action')?.toString() === 'general-setup') {
                setTimeout(function () {
                    const target = document.querySelector('.general_setup_auto_fill');
                    if (target) {
                        target.setAttribute('data-next-action', 'price-setup');
                        target.click();
                    }
                }, 2000);
            }


            $button.removeAttr('data-next-action');         // removes HTML attribute
            $button.removeData('next-action');              // removes jQuery cached data
            if ($button[0] && $button[0].dataset) {
                delete $button[0].dataset.nextAction;       // removes DOM dataset property
            }


            // Stop animation after short delay
            setTimeout(() => {
                $shortDescription.closest('.outline-wrapper').removeClass('outline-animating');
            }, 500);

            // Re-enable button and reset texts
            $button.prop('disabled', false);
            $button.find('.btn-text').text('Re-generate');
            $aiText.addClass('d-none').removeClass('ai-text-animation-visible');
        }
    });
});
