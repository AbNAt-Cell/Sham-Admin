$(document).off('click', '.auto_fill_title').on('click', '.auto_fill_title', function () {
    const $button = $(this);
    const lang = $button.data('lang');
    const route = $button.data('route');
    const name = $('#en_name').val();
    const $editorContainer = $('.title-container-' + lang);
    const $aiText = $button.find('.ai-text-animation');

    const existingTitle = $button.data('item')?.name || "";

    $editorContainer.addClass('outline-animating');
    $button.prop('disabled', true);
    $button.find('.btn-text').text('');
    $aiText.removeClass('d-none').addClass('ai-text-animation-visible');


    const modifiedLang = lang === 'default' ? 'en' : lang;

    $.ajax({
        url: route,
        type: 'GET',
        dataType: 'json',
        data: {

            name: name,
            langCode: lang
        },
        success: function (response) {
            $('#' + lang + '_name').val(response.data);
        },
        error: function (xhr, status, error) {
            $('#' + lang + '_name').val(existingTitle);
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
            setTimeout(() => {
                $editorContainer.removeClass('outline-animating');
            }, 500);
            $button.prop('disabled', false);
            $button.find('.btn-text').text('Re-generate');
            $aiText.addClass('d-none').removeClass('ai-text-animation-visible');
        }
    });
});
