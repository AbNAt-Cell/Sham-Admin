"use strict";

let isTransitioning = false;

$(document).on('click', '[data-toggle="offcanvas"]', function () {
    if (isTransitioning) return;
    isTransitioning = true;

    let target = $(this).attr('data-target');
    let $newOffcanvas = $(target);

    let $overlay = $newOffcanvas.data('overlayElement');
    if (!$overlay || !$overlay.length) {
        $overlay = $('<div class="overlay"></div>').insertBefore($newOffcanvas);
        $newOffcanvas.data('overlayElement', $overlay);
    }

    let $currentOffcanvas = $('.offcanvas.open');
    if ($currentOffcanvas.length && !$currentOffcanvas.is($newOffcanvas)) {
        closeOffcanvas($currentOffcanvas);
        setTimeout(() => {
            openOffcanvas($newOffcanvas, $overlay);
            isTransitioning = false;
        }, 300);
    } else {
        openOffcanvas($newOffcanvas, $overlay);
        isTransitioning = false;
    }
});

$(document).on('click', '.overlay', function () {
    let $offcanvas = $(this).next('.offcanvas');
    closeOffcanvas($offcanvas);
});

$(document).on('click', '[data-dismiss="offcanvas"]', function () {
    let $offcanvas = $(this).closest('.offcanvas');
    closeOffcanvas($offcanvas);
});

$(document).on('keydown', function (e) {
    if (e.key === 'Escape' || e.keyCode === 27) {
        let $openOffcanvas = $('.offcanvas.open');
        if ($openOffcanvas.length) {
            closeOffcanvas($openOffcanvas);
        }
    }
});

function openOffcanvas($offcanvas, $overlay) {
    $offcanvas.addClass('open');
    $overlay.addClass('active');
    $('body').addClass('modal-open');
}

function closeOffcanvas($offcanvas) {
    let $overlay = $offcanvas.data('overlayElement');
    $offcanvas.removeClass('open');
    if ($overlay) $overlay.removeClass('active');
    $('body').removeClass('modal-open');
}
